// Package daemon holds shared constants for the aegis session daemon.
package daemon

const (
	// SocketPath is the Unix domain socket the daemon listens on.
	SocketPath = "/tmp/aegis-daemon.sock"
	// PIDFile records the daemon process ID.
	PIDFile = "/tmp/aegis-daemon.pid"
)
