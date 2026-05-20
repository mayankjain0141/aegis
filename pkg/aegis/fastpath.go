package aegis

import (
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/mayjain/aegis/pkg/aegis/allowlist"
	"github.com/mayjain/aegis/pkg/aegis/bloom"
)

// FastPath checks whether a request can be short-circuited before rule evaluation.
// Returns (allow=true, ruleName) on a hit, (false, "") on a miss.
type FastPath interface {
	Check(req *Request, argsJSON string) (allow bool, ruleName string)
	// allowlistForCWD is used by the signal computer to apply allowlist mutations.
	allowlistForCWD(cwd string) *allowlist.Config
	// setAllowlist replaces the allowlist for the given key (empty = fixed for all CWDs).
	setAllowlist(key string, cfg *allowlist.Config)
	// loadCWD pre-loads the allowlist for a specific CWD.
	loadCWD(cwd string)
}

type defaultFastPath struct {
	bloom      *bloom.Filter
	allowlists map[string]*allowlist.Config
	mu         sync.RWMutex
	sfGroup    singleflight.Group
}

func newDefaultFastPath(bl *bloom.Filter, als map[string]*allowlist.Config) FastPath {
	if bl == nil {
		bl = bloom.New(1000, 0.01)
	}
	if als == nil {
		als = make(map[string]*allowlist.Config)
	}
	return &defaultFastPath{bloom: bl, allowlists: als}
}

func (fp *defaultFastPath) Check(req *Request, argsJSON string) (bool, string) {
	key := bloom.CanonicalKey(req.Tool, req.Arguments)
	if fp.bloom.Contains(key) {
		return true, "fast_path_allow"
	}

	al := fp.allowlistForCWD(req.CWD)
	if al == nil {
		return false, ""
	}
	if cmd, ok := req.Arguments["command"]; ok {
		if cmdStr, ok := cmd.(string); ok && al.MatchesCommand(cmdStr) {
			return true, "allowlist_command"
		}
	}
	for _, k := range []string{"path", "file", "filename"} {
		if p, ok := req.Arguments[k]; ok {
			if pathStr, ok := p.(string); ok && al.IsSafePath(pathStr) {
				return true, "allowlist_path"
			}
		}
	}
	return false, ""
}

func (fp *defaultFastPath) allowlistForCWD(cwd string) *allowlist.Config {
	fp.mu.RLock()
	if fixed, ok := fp.allowlists[""]; ok {
		fp.mu.RUnlock()
		return fixed
	}
	if cached, ok := fp.allowlists[cwd]; ok {
		fp.mu.RUnlock()
		return cached
	}
	fp.mu.RUnlock()

	v, _, _ := fp.sfGroup.Do(cwd, func() (any, error) {
		cfg := allowlist.Load(cwd)
		fp.mu.Lock()
		fp.allowlists[cwd] = cfg
		fp.mu.Unlock()
		return cfg, nil
	})
	return v.(*allowlist.Config)
}

func (fp *defaultFastPath) setAllowlist(key string, cfg *allowlist.Config) {
	fp.mu.Lock()
	fp.allowlists[key] = cfg
	fp.mu.Unlock()
}

func (fp *defaultFastPath) loadCWD(cwd string) {
	fp.mu.Lock()
	fp.allowlists[cwd] = allowlist.Load(cwd)
	fp.mu.Unlock()
}
