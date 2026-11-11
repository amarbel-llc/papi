package authproxy

import (
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
