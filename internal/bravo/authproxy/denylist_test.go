package authproxy

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	denyIDA = "3d42781784af9c27fd66550539775a88"
	denyIDB = "00112233445566778899aabbccddeeff"
)

func TestParseDenyList(t *testing.T) {
	d, err := ParseDenyList([]byte("# revoked 2026-11-12\n\n" + denyIDA + "   # stolen laptop\n" + denyIDB + "\n"))
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}
	if !d.Denied(denyIDA) || !d.Denied(denyIDB) {
		t.Error("listed ids not denied")
	}
	if d.Denied("ffffffffffffffffffffffffffffffff") {
		t.Error("unlisted id denied")
	}
	if d.Denied("") {
		t.Error("empty id denied")
	}
}

func TestParseDenyListRejectsMalformedLines(t *testing.T) {
	for name, body := range map[string]string{
		"short id":      "abcd\n",
		"uppercase":     strings.ToUpper(denyIDA) + "\n",
		"non hex":       strings.Repeat("g", 32) + "\n",
		"id then junk":  denyIDA + " junk\n",
		"two ids":       denyIDA + " " + denyIDB + "\n",
		"too long":      denyIDA + "00\n",
		"inline marker": denyIDA + "#x\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDenyList([]byte(body)); err == nil {
				t.Errorf("accepted %q", body)
			}
		})
	}
}

func TestEmptyDenyListIsValid(t *testing.T) {
	d, err := ParseDenyList(nil)
	if err != nil || d.Denied(denyIDA) {
		t.Fatalf("empty list: %v", err)
	}
}

func TestNilDenyListDeniesNothing(t *testing.T) {
	var d *DenyList
	if d.Denied(denyIDA) {
		t.Error("nil list denied an id")
	}
}

func TestLoadDenyListMissingFileIsAnError(t *testing.T) {
	if _, err := LoadDenyList(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a configured but absent deny file must be an error, not an empty list")
	}
}

func TestDenyListHotReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny")
	if err := os.WriteFile(path, []byte(denyIDA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDenyList(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Denied(denyIDB) {
		t.Fatal("B denied before it was listed")
	}
	if err := os.WriteFile(path, []byte(denyIDA+"\n"+denyIDB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if !d.Denied(denyIDB) {
		t.Error("newly listed id not denied after the file changed")
	}
}

// A mid-write or corrupted file must not un-deny anything: the last good set stays.
func TestDenyListKeepsLastGoodSetOnBadReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny")
	if err := os.WriteFile(path, []byte(denyIDA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDenyList(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if !d.Denied(denyIDA) {
		t.Error("a corrupt reload dropped a denied id")
	}
}

// touch rewrites path and moves its mtime forward so the reload check sees a change.
func touch(t *testing.T, path, body string, offset time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(offset)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// A rejected reload must be loud: the operator believes a revocation took effect.
func TestBadDenyReloadIsLoggedOncePerFileVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny")
	touch(t, path, denyIDA+"\n", 0)
	d, err := LoadDenyList(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	d.Logger = slog.New(slog.NewTextHandler(&logs, nil))

	touch(t, path, denyIDA+"\n"+"garbage\n", time.Minute)
	for range 5 { // many requests, one file version
		_ = d.Denied(denyIDB)
	}
	out := logs.String()
	if !strings.Contains(out, path) || !strings.Contains(out, "line 2") {
		t.Errorf("log should name the file and the bad line, got %q", out)
	}
	if n := strings.Count(out, "deny list reload rejected"); n != 1 {
		t.Errorf("logged %d times for one file version, want 1:\n%s", n, out)
	}
	if !d.Denied(denyIDA) {
		t.Error("the last good set was lost")
	}
}

// Deny lists only grow. A reload that would empty a non-empty set is refused (the
// signature of a truncated, mid-write file); to shrink the list, restart the verifier.
func TestDenyReloadRefusesToEmptyANonEmptySet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny")
	touch(t, path, denyIDA+"\n", 0)
	d, err := LoadDenyList(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	d.Logger = slog.New(slog.NewTextHandler(&logs, nil))

	touch(t, path, "", time.Minute)
	if !d.Denied(denyIDA) {
		t.Error("an empty file un-denied a grant")
	}
	if !strings.Contains(logs.String(), "deny list reload rejected") {
		t.Errorf("refusal not logged: %q", logs.String())
	}

	// A larger set is accepted, and a comment-only file is as empty as an empty one.
	touch(t, path, denyIDA+"\n"+denyIDB+"\n", 2*time.Minute)
	if !d.Denied(denyIDB) {
		t.Error("a grown list was not applied")
	}
	touch(t, path, "# nothing\n", 3*time.Minute)
	if !d.Denied(denyIDB) {
		t.Error("a comment-only file un-denied a grant")
	}
}

func TestEmptyInitialDenyFileIsAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny")
	touch(t, path, "# none yet\n", 0)
	d, err := LoadDenyList(path)
	if err != nil {
		t.Fatalf("an empty deny file is the normal starting state: %v", err)
	}
	touch(t, path, denyIDA+"\n", time.Minute)
	if !d.Denied(denyIDA) {
		t.Error("first entry not applied")
	}
}
