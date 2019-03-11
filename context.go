package main

import (
	"context"
	"encoding/hex"
	"sync"

	"github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

var (
	// ContextKeyConn is a context key for use with Contexts in this package.
	// The associated value will be of type gossh.ServerConn.
	ContextKeyConn = &contextKey{"ssh-conn"}

	// ContextLogKey is the context key used to access the logger
	ContextKeyLogger = &contextKey{"logger"}
)

// Context is a package specific context interface. It exposes connection
// metadata and allows new values to be easily written to it. It's used in
// authentication handlers and callbacks, and its underlying context.Context is
// exposed on Session in the session Handler. A connection-scoped lock is also
// embedded in the context to make it easier to limit operations per-connection.
type Context interface {
	context.Context
	sync.Locker

	// User returns the username used when establishing the SSH connection.
	User() string

	// SetValue allows you to easily write new values into the underlying context.
	SetValue(key, value interface{})

	// Log returns a logger
	Logger() logrus.FieldLogger
}

type sshContext struct {
	context.Context
	*sync.Mutex
}

func newContext(conn ssh.ConnMetadata, log logrus.FieldLogger) (*sshContext, context.CancelFunc) {
	innerCtx, cancel := context.WithCancel(context.Background())
	ctx := &sshContext{innerCtx, &sync.Mutex{}}
	ctx.SetValue(ContextKeyConn, conn)
	ctx.SetValue(ContextKeyLogger, log.WithFields(logrus.Fields{
		"SessionID":     hex.EncodeToString(conn.SessionID()),
		"ClientVersion": string(conn.ClientVersion()),
		"ServerVersion": string(conn.ServerVersion()),
		"User":          conn.User(),
		"LocalAddr":     conn.LocalAddr(),
		"RemoteAddr":    conn.RemoteAddr(),
	}))

	return ctx, cancel
}

func (ctx *sshContext) SetValue(key, value interface{}) {
	ctx.Context = context.WithValue(ctx.Context, key, value)
}

func (ctx *sshContext) User() string {
	return ctx.Value(ContextKeyConn).(ssh.ConnMetadata).User()
}

func (ctx *sshContext) Logger() logrus.FieldLogger {
	return ctx.Value(ContextKeyLogger).(logrus.FieldLogger)
}
