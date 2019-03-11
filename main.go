package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}
type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

var connectedUsers sync.Map

var authorizedKeysFile string
var privateKeyFile string
var socketPath string
var socketPerms uint
var listen string

func init() {
	flag.StringVar(&listen, "listen", ":2222", "Listen address")
	flag.StringVar(&authorizedKeysFile, "authorized_keys", "authorized_keys", "Path to the authorized keys")
	flag.StringVar(&privateKeyFile, "private_key", "id_rsa", "Path to the server rsa key")
	flag.StringVar(&socketPath, "sockets", "/var/run/revssh", "Path to store sockets")
	flag.UintVar(&socketPerms, "perms", 0660, "Permissions to use on sockets")
	flag.Parse()
}

func parseAuthorizedKeys() map[string]ssh.PublicKey {
	r := make(map[string]ssh.PublicKey)
	f, err := os.Open(authorizedKeysFile)
	if err != nil {
		logrus.WithError(err).Fatalf("Unable to open authorized keys file %v", authorizedKeysFile)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		out, comment, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			logrus.WithError(err).Warn("unable to parse key")
			continue
		}
		r[strings.TrimSpace(comment)] = out
	}

	return r
}
func main() {
	authorizedKeys := parseAuthorizedKeys()

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := connectedUsers.Load(conn.User()); ok {
				return nil, fmt.Errorf("maximum number of connections reached")
			}
			if akey, found := authorizedKeys[conn.User()]; found {
				if bytes.Equal(akey.Marshal(), key.Marshal()) {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, fmt.Errorf("new server, who dis?")
		},
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to load private key (%v)", privateKeyFile)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		logrus.Fatalf("Failed to listen on %v (%s)", listen, err)
	}

	// Accept all connections
	logrus.Infof("Listening on %v...", listen)
	for {
		rawConn, err := listener.Accept()
		if err != nil {
			logrus.Warnf("Failed to accept incoming connection (%s)", err)
			continue
		}

		go handleConnection(rawConn, config)
	}
}

func handleConnection(rawConn net.Conn, config *ssh.ServerConfig) {
	// Before use, a handshake must be performed on the incoming net.Conn.
	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)
	if err != nil {
		log.Printf("Failed to handshake (%s)", err)
		return
	}

	connectedUsers.Store(sshConn.User(), nil)
	// IDEA: timeout if connection not set up in a given amount of time

	ctx, cancel := newContext(sshConn, logrus.NewEntry(logrus.StandardLogger()))
	defer func() {
		ctx.Logger().Info("Disconnecting")
		cancel()
		connectedUsers.Delete(sshConn.User())
	}()

	ctx.Logger().Info("New SSH connection")

	go handleRequests(ctx, reqs)

	for ch := range chans {
		ctx.Logger().WithField("ChannelType", ch.ChannelType()).Error("A root channel was requested")
		ch.Reject(ssh.Prohibited, ssh.Prohibited.String())
	}
}

func handleRequests(ctx Context, in <-chan *ssh.Request) {
	forwarded := 0
	time.AfterFunc(time.Second*30, func() {
		if forwarded == 0 {
			ctx.Logger().Warn("Timeout while waiting for tcpip-forward")
			ctx.Value(ContextKeyConn).(*ssh.ServerConn).Close()
		}
	})
	for req := range in {
		switch req.Type {
		case "tcpip-forward":
			if forwarded == 1 {
				ctx.Logger().Error("Multiple tcpip-forwards attempted")
				req.Reply(false, nil)
			}
			forwarded++
			req.Reply(handleTCPIPForward(ctx, req))
		case "keepalive@openssh.com":
			req.Reply(false, nil)
		default:
			ctx.Logger().WithField("RequestType", req.Type).Warn("Ignoring request")
			req.Reply(false, nil)
		}
	}
}

func handleTCPIPForward(ctx Context, req *ssh.Request) (ok bool, payload []byte) {
	var reqPayload remoteForwardRequest
	if err := ssh.Unmarshal(req.Payload, &reqPayload); err != nil {
		ctx.Logger().WithError(err).Error("Unable to parse request payload")
		return false, []byte{}
	}

	sockName := filepath.Join(socketPath, ctx.User()+".sock")

	logCtx := ctx.Logger().WithFields(logrus.Fields{
		"Module": "TCPUPForward",
		"Socket": sockName,
	})

	// A little bit brute force but... meh
	os.Remove(sockName)

	ln, err := net.Listen("unix", sockName)
	if err != nil {
		logCtx.WithError(err).Error("Unable to create listening socket")
		return false, []byte{}
	}
	os.Chmod(sockName, os.FileMode(socketPerms))

	go func() {
		conn := ctx.Value(ContextKeyConn).(*ssh.ServerConn)
		var o sync.Once

		closer := func() {
			logCtx.Info("Closing forwarding socket")
			ln.Close()
			os.Remove(ctx.User() + ".sock")
		}

		go func() {
			<-ctx.Done()
			o.Do(closer)
		}()

		defer func() {
			o.Do(closer)
		}()

		var counter uint64

		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != context.Canceled {
					logCtx.WithError(err).Error("Unable to accept request")
				}
				break
			}

			counter++
			logCtx := logCtx.WithField("SubConnection", counter)
			logCtx.Info("Opening sub connection")

			payload := ssh.Marshal(&remoteForwardChannelData{
				DestAddr:   reqPayload.BindAddr,
				DestPort:   uint32(reqPayload.BindPort),
				OriginAddr: "127.0.0.1",
				OriginPort: uint32(22),
			})

			ch, reqs, err := conn.OpenChannel("forwarded-tcpip", payload)
			if err != nil {
				logCtx.WithError(err).Error("Unable to open sub connection")
				c.Close()
				return
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				defer ch.Close()
				defer c.Close()
				io.Copy(ch, c)
			}()
			defer ch.Close()
			defer c.Close()
			io.Copy(c, ch)
			logCtx.Info("Closing sub connection")
		}
	}()

	return true, ssh.Marshal(&remoteForwardSuccess{uint32(22)})
}
