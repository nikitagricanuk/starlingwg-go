package persist

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// FileStore persists each key as one file in dir, written atomically
// (temp file + rename) so a process kill mid-write can never leave a
// corrupt, partially-written file behind -- important given the whole
// point of this package is surviving exactly that kind of abrupt
// termination. Keys are hex-encoded into filenames since they may contain
// characters (":", "/") that aren't safe as path components (e.g. a
// ControlAddr like "203.0.113.1:41820").
type FileStore struct {
	dir string
}

var _ Store = (*FileStore)(nil)

// NewFileStore uses dir for storage, creating it (mode 0700) if it
// doesn't exist.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("persist: create store dir: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

func (f *FileStore) path(key string) string {
	return filepath.Join(f.dir, hex.EncodeToString([]byte(key))+".json")
}

func (f *FileStore) Save(_ context.Context, key string, data []byte) error {
	final := f.path(key)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("persist: write temp file: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("persist: rename into place: %w", err)
	}
	return nil
}

func (f *FileStore) Load(_ context.Context, key string) ([]byte, error) {
	data, err := os.ReadFile(f.path(key))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("persist: read file: %w", err)
	}
	return data, nil
}

func (f *FileStore) Delete(_ context.Context, key string) error {
	err := os.Remove(f.path(key))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("persist: remove file: %w", err)
	}
	return nil
}
