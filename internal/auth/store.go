package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Store persists the OAuth token between runs.
type Store interface {
	Load() (Token, error)
	Save(Token) error
	Delete() error
}

// FileStore keeps the token in a JSON file with mode 0600. Writes are atomic:
// temp file in the same directory, fsync, then rename.
type FileStore struct {
	Path string
}

// Load returns the stored token. A missing file is not an error and yields a
// zero Token, so a first start is clean. OID is not persisted and is decoded
// from the access token here.
func (s *FileStore) Load() (Token, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Token{}, nil
	}
	if err != nil {
		return Token{}, fmt.Errorf("reading token store: %w", err)
	}
	var tok Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return Token{}, fmt.Errorf("decoding token store: %w", err)
	}
	if tok.AccessToken != "" {
		if c, err := ParseClaims(tok.AccessToken); err == nil {
			tok.OID = c.OID
			tok.MailNickname = c.MailNickname
			tok.jwtExp = c.Exp
		}
	}
	return tok, nil
}

// Save writes the token atomically. The directory is created (0700) and the
// file is written with 0600.
func (s *FileStore) Save(tok Token) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating token store directory: %w", err)
	}
	data, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("encoding token: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".token-*.tmp")
	if err != nil {
		return fmt.Errorf("creating token temp file: %w", err)
	}
	tmpName := tmp.Name()
	// Ignore cleanup errors; on success the rename already moved the file.
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("setting token file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing token file: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("replacing token store: %w", err)
	}
	return nil
}

// Delete removes the token file. A missing file is ignored.
func (s *FileStore) Delete() error {
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing token store: %w", err)
	}
	return nil
}
