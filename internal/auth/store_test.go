package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readJSON decodes the raw token store file.
func readJSON(t *testing.T, s *FileStore) map[string]any {
	t.Helper()
	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFileStoreMissingFileIsEmpty(t *testing.T) {
	store := &FileStore{Path: filepath.Join(t.TempDir(), "absent.json")}
	tok, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if tok != (Token{}) {
		t.Errorf("want zero token, got %+v", tok)
	}
}

func TestFileStorePermissionsAndRoundTrip(t *testing.T) {
	store := newFileStore(t)
	want := Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode = %o, want 600", got)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AccessToken != want.AccessToken || loaded.RefreshToken != want.RefreshToken {
		t.Errorf("loaded = %+v", loaded)
	}
	if !loaded.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("expires_at = %v, want %v", loaded.ExpiresAt, want.ExpiresAt)
	}
}

func TestFileStoreCreatesDirPrivate(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "state")
	store := &FileStore{Path: filepath.Join(nested, "token.json")}
	if err := store.Save(Token{AccessToken: "x"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("dir mode = %o, want 700", got)
	}
}

func TestFileStoreAtomicNoTempLeftover(t *testing.T) {
	dir := t.TempDir()
	store := &FileStore{Path: filepath.Join(dir, "token.json")}
	for i := range 3 {
		if err := store.Save(Token{AccessToken: "a", RefreshToken: "r"}); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "token.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("unexpected files after save: %v", names)
	}
}

func TestFileStoreJSONFields(t *testing.T) {
	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	raw := readJSON(t, store)
	for _, key := range []string{"access_token", "refresh_token", "expires_at"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON field %q in %v", key, raw)
		}
	}
}

func TestFileStoreDelete(t *testing.T) {
	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(); err != nil {
		t.Errorf("delete must be idempotent: %v", err)
	}
	tok, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if tok != (Token{}) {
		t.Errorf("want zero token after delete, got %+v", tok)
	}
}

func TestFileStoreLoadDecodesOID(t *testing.T) {
	store := newFileStore(t)
	jwt := fakeJWT(t, map[string]any{"oid": "oid-x", "mailnickname": "mx"})
	if err := store.Save(Token{AccessToken: jwt}); err != nil {
		t.Fatal(err)
	}
	tok, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if tok.OID != "oid-x" || tok.MailNickname != "mx" {
		t.Errorf("claims = %q, %q", tok.OID, tok.MailNickname)
	}
}
