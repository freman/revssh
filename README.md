# Reverse SSH server

Because I'm tired of all the magic required to reliably terminate multiple reverse ssh connections.

# Setup

```
groupadd -r revssh
userdd -r -s -g revssh revssh
mkdir /etc/revssh
cd /etc/revssh
ssh-keygen -t rsa -f id_rsa
vim authorized_keys
chown -R revssh.revssh
```

## openrc script

```
#!/sbin/openrc-run

name="$RC_SVCNAME"
command_user="revssh"
command_group="revssh"
command="/usr/local/bin/${name}"
command_args="-authorized_keys /etc/revssh/authorized_keys -private_key /etc/revssh/id_rsa -listen :61022 -sockets /var/run/revssh"
command_background="yes"
pidfile="/var/run/$RC_SVCNAME.pid"

depend() {
	use logger dns entropy
}

checkconfig() {
	checkpath --mode 0755 --directory --owner "$command_user:$command_group" "/var/run/revssh"
}

start_pre() {
	if [ "${RC_CMD}" != "restart" ] ; then
		checkconfig || return $?
	fi
}
```

# Authorized_keys

The comment on the key must match the username logging in, otherwise it's a standard authorized_keys file.

# ~/.ssh/config

```
Host *.sock
ProxyCommand socat - UNIX-CLIENT:/var/run/revssh/%h
```

Then you can `ssh foo.sock` and it'll magic!


# Sample client usage

Reduntant reverse ssh connections over 3g with multiple ISPs making use of some source routing magic

```
/usr/lib/autossh/autossh -M 0 -o ExitOnForwardFailure=yes -o ServerAliveInterval 30 -o ServerAliveCountMax 3 -N -R 22:localhost:22 -b 10.11.1.13 -p 61022 -i /home/ubuntu/.ssh/optus optus@example.com
/usr/lib/autossh/autossh -M 0 -o ExitOnForwardFailure=yes -o ServerAliveInterval 30 -o ServerAliveCountMax 3 -N -R 22:localhost:22 -b 10.11.1.12 -p 61022 -i /home/ubuntu/.ssh/vodafone vodafone@example.com
/usr/lib/autossh/autossh -M 0 -o ExitOnForwardFailure=yes -o ServerAliveInterval 30 -o ServerAliveCountMax 3 -N -R 22:localhost:22 -b 10.11.1.11 -p 61022 -i /home/ubuntu/.ssh/telstra telstra@example.com
```
