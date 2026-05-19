package policy

import (
	"strings"

	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// suidChmod returns true if the command sets the SUID bit via chmod.
func suidChmod(b *signals.SignalBundle) bool {
	for _, cmd := range b.Command.Commands {
		if cmd.Binary != "chmod" {
			continue
		}
		for _, arg := range cmd.Args {
			if arg == "+s" || arg == "u+s" || arg == "g+s" {
				return true
			}
			if strings.Contains(arg, "+s") {
				return true
			}
			// Numeric octal mode starting with 4 (e.g. 4755)
			if len(arg) == 4 && arg[0] == '4' {
				return true
			}
		}
	}
	return false
}

// writesCronDir returns true if any path targets cron directories.
func writesCronDir(b *signals.SignalBundle) bool {
	cronDirs := []string{"/etc/cron", "/var/spool/cron", "/etc/crontab"}
	for _, p := range b.Path.Paths {
		for _, dir := range cronDirs {
			if strings.HasPrefix(p.Normalized, dir) {
				return true
			}
		}
	}
	return false
}
