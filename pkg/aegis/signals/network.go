package signals

import (
	"net"
	"net/url"
	"strings"
)

// NetworkSignal is Signal 4: network destination and intent analysis.
type NetworkSignal struct {
	Hosts        []AnalyzedHost
	HasDataFlag  bool
	HasStdinPipe bool
	Score        float64
}

// AnalyzedHost holds risk analysis for a single network destination.
type AnalyzedHost struct {
	Host        string
	IsInternal  bool
	IsKnownSafe bool
	IsKnownBad  bool
}

var knownSafeHosts = map[string]bool{
	"github.com": true, "raw.githubusercontent.com": true,
	"npmjs.org": true, "registry.npmjs.org": true,
	"pypi.org": true, "files.pythonhosted.org": true,
	"go.dev": true, "pkg.go.dev": true, "sum.golang.org": true, "proxy.golang.org": true,
	"crates.io": true, "static.crates.io": true,
	"rubygems.org": true, "api.rubygems.org": true,
	"nuget.org": true, "api.nuget.org": true,
	"packagist.org": true,
	"maven.org": true, "repo.maven.apache.org": true,
	"brew.sh": true, "formulae.brew.sh": true,
	"apt.postgresql.org": true,
}

// AnalyzeNetwork computes NetworkSignal from extracted hosts and command args.
func AnalyzeNetwork(hosts []string, args []string, hasDataFlag bool, hasStdinPipe bool) NetworkSignal {
	var sig NetworkSignal
	sig.HasDataFlag = hasDataFlag
	sig.HasStdinPipe = hasStdinPipe

	for _, h := range hosts {
		ah := classifyHost(h)
		sig.Hosts = append(sig.Hosts, ah)
	}

	sig.Score = computeNetworkScore(&sig)
	return sig
}

// AnalyzeNetworkFromCommand derives network signal from command analysis.
func AnalyzeNetworkFromCommand(cmd CommandSignal, args []string) NetworkSignal {
	var hosts []string
	hasDataFlag := false
	hasStdinPipe := false

	for _, c := range cmd.Commands {
		if isNetworkBinary(c.Binary) {
			hosts = append(hosts, extractHostsFromArgs(c.Binary, c.Args)...)
			if hasDataFlags(c.Args) {
				hasDataFlag = true
			}
		}
	}

	for _, c := range cmd.Commands {
		if isShellInterpreter(c.Binary) {
			hasStdinPipe = true
		}
	}

	return AnalyzeNetwork(hosts, args, hasDataFlag, hasStdinPipe)
}

// AnalyzeNetworkFromExtracted builds network signal using hosts from network command arguments only.
// It does NOT use cmd.Hosts (pre-extracted by shell extractor) because the extractor's
// looksLikeHost heuristic has false positives (e.g., "file.txt" looks like a host).
func AnalyzeNetworkFromExtracted(cmd CommandSignal) NetworkSignal {
	hasDataFlag := false
	hasStdinPipe := false
	var hosts []string

	for _, c := range cmd.Commands {
		if isNetworkBinary(c.Binary) {
			hosts = append(hosts, extractHostsFromArgs(c.Binary, c.Args)...)
			if hasDataFlags(c.Args) {
				hasDataFlag = true
			}
		}
		if isShellInterpreter(c.Binary) {
			hasStdinPipe = true
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, h := range hosts {
		if !seen[h] {
			seen[h] = true
			unique = append(unique, h)
		}
	}

	return AnalyzeNetwork(unique, nil, hasDataFlag, hasStdinPipe)
}

func classifyHost(raw string) AnalyzedHost {
	ah := AnalyzedHost{Host: raw}

	// Parse URL to extract hostname
	hostname := raw
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			hostname = u.Hostname()
		}
	} else if idx := strings.Index(raw, "/"); idx != -1 {
		hostname = raw[:idx]
	}
	// Strip port
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}

	lower := strings.ToLower(hostname)

	if isInternalHost(lower) {
		ah.IsInternal = true
		return ah
	}

	if knownSafeHosts[lower] || isKnownSafeDomain(lower) {
		ah.IsKnownSafe = true
	}

	return ah
}

func isInternalHost(hostname string) bool {
	if hostname == "localhost" || hostname == "" {
		return true
	}
	if strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal") {
		return true
	}
	// Parse IP
	ip := net.ParseIP(hostname)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func isKnownSafeDomain(hostname string) bool {
	// Check subdomain of known-safe
	for safe := range knownSafeHosts {
		if strings.HasSuffix(hostname, "."+safe) {
			return true
		}
	}
	return false
}

func isNetworkBinary(binary string) bool {
	networkBinaries := map[string]bool{
		"curl": true, "wget": true, "scp": true, "rsync": true,
		"nc": true, "ncat": true, "socat": true, "telnet": true,
		"ftp": true, "sftp": true, "ssh": true,
	}
	return networkBinaries[binary]
}

func isShellInterpreter(binary string) bool {
	interpreters := map[string]bool{
		"bash": true, "sh": true, "zsh": true, "fish": true, "dash": true,
	}
	return interpreters[binary]
}

func extractHostsFromArgs(binary string, args []string) []string {
	var hosts []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, "://") {
			hosts = append(hosts, arg)
			continue
		}
		// For scp: user@host:path
		if binary == "scp" && strings.Contains(arg, "@") {
			parts := strings.SplitN(arg, ":", 2)
			if len(parts) == 2 {
				userHost := parts[0]
				if idx := strings.Index(userHost, "@"); idx != -1 {
					hosts = append(hosts, userHost[idx+1:])
				}
			}
			continue
		}
		// For nc/telnet: positional host argument
		if (binary == "nc" || binary == "ncat" || binary == "telnet") && strings.Contains(arg, ".") {
			hosts = append(hosts, arg)
		}
	}
	return hosts
}

func hasDataFlags(args []string) bool {
	flags := map[string]bool{
		"-d": true, "--data": true, "--data-binary": true, "--data-raw": true,
		"-T": true, "-F": true, "--form": true,
		"--post-file": true, "--upload-file": true,
		"--data-urlencode": true,
	}
	for _, arg := range args {
		key := strings.SplitN(arg, "=", 2)[0]
		if flags[key] {
			return true
		}
		// Also check @file pattern (curl -d @file)
		if strings.HasPrefix(arg, "@") {
			return true
		}
	}
	return false
}

// RecomputeNetworkScore updates a NetworkSignal's score after host classifications change.
func RecomputeNetworkScore(sig NetworkSignal) NetworkSignal {
	sig.Score = computeNetworkScore(&sig)
	return sig
}

func computeNetworkScore(sig *NetworkSignal) float64 {
	if len(sig.Hosts) == 0 {
		return 0.00
	}

	// Check for known-bad first
	for _, h := range sig.Hosts {
		if h.IsKnownBad {
			return 0.95
		}
	}

	// Classify the worst-case host in the set.
	// A host is trusted if it is KnownSafe OR Internal; unknown only if neither.
	hasUnknown := false
	hasTrusted := false
	allTrusted := true
	for _, h := range sig.Hosts {
		trusted := h.IsKnownSafe || h.IsInternal
		if trusted {
			hasTrusted = true
		} else {
			hasUnknown = true
			allTrusted = false
		}
	}
	_ = hasTrusted

	// For scoring purposes, further distinguish KnownSafe vs Internal among trusted hosts.
	allSafe := true     // all hosts are KnownSafe (public registries, etc.)
	allInternal := true // all hosts are Internal (LAN, localhost)
	for _, h := range sig.Hosts {
		if !h.IsKnownSafe {
			allSafe = false
		}
		if !h.IsInternal {
			allInternal = false
		}
	}

	isWrite := sig.HasDataFlag || sig.HasStdinPipe

	if !isWrite {
		// Read operations
		if allSafe {
			return 0.05
		}
		if allInternal {
			return 0.10
		}
		if allTrusted {
			return 0.10 // mixed safe+internal is still trusted
		}
		return 0.30
	}

	// Write (data upload) operations
	if sig.HasStdinPipe {
		return 0.90
	}
	if hasUnknown && sig.HasDataFlag {
		return 0.85
	}
	if hasUnknown {
		return 0.60
	}
	// All trusted (safe or internal)
	if allInternal {
		return 0.25
	}
	if allSafe {
		return 0.20
	}
	return 0.25 // mixed trusted — treat as internal-level risk
}
