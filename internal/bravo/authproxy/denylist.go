package authproxy

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var grantIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// DenyList is the set of revoked login-grant ids (RFC-0001 §5.2.1), read from a file
// of one id per line. Blank lines and `#` comments are ignored, and an id may be
// followed by whitespace and a `# comment`. Like the registry it hot-reloads when the
// file's mtime advances, but a failed or corrupt reload KEEPS the last good set: for a
// revocation list the safe failure is "still denied", never "forgotten".
type DenyList struct {
	mu      sync.RWMutex
	ids     map[string]bool
	path    string
	modTime time.Time
}

// ParseDenyList parses deny-file bytes strictly; a malformed line is an error so a typo
// is noticed at load rather than silently failing to revoke.
func ParseDenyList(data []byte) (*DenyList, error) {
	ids := map[string]bool{}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		id, rest := fields[0], strings.Join(fields[1:], " ")
		if !grantIDRE.MatchString(id) {
			return nil, fmt.Errorf("deny list line %d: %q is not a 32-char lowercase hex grant id", n+1, id)
		}
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return nil, fmt.Errorf("deny list line %d: unexpected text after the id (use `# comment`)", n+1)
		}
		ids[id] = true
	}
	return &DenyList{ids: ids}, nil
}

// LoadDenyList reads path and remembers it for hot reload. A configured file that does
// not exist is an error: an operator who named a deny file expects it to be enforced.
func LoadDenyList(path string) (*DenyList, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat deny list %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read deny list %s: %w", path, err)
	}
	d, err := ParseDenyList(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	d.path, d.modTime = path, info.ModTime()
	return d, nil
}

// Denied reports whether id is revoked. A nil list denies nothing.
func (d *DenyList) Denied(id string) bool {
	if d == nil || id == "" {
		return false
	}
	d.maybeReload()
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ids[id]
}

func (d *DenyList) maybeReload() {
	if d.path == "" {
		return
	}
	info, err := os.Stat(d.path)
	if err != nil {
		return
	}
	d.mu.RLock()
	stale := info.ModTime().After(d.modTime)
	d.mu.RUnlock()
	if !stale {
		return
	}
	data, err := os.ReadFile(d.path)
	if err != nil {
		return
	}
	parsed, err := ParseDenyList(data)
	if err != nil {
		return // keep the last good set
	}
	d.mu.Lock()
	d.ids = parsed.ids
	d.modTime = info.ModTime()
	d.mu.Unlock()
}
