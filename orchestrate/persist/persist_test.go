package persist

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func testStores(t *testing.T) map[string]Store {
	t.Helper()
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return map[string]Store{
		"MemoryStore": NewMemoryStore(),
		"FileStore":   fs,
	}
}

func TestStoreRoundTrip(t *testing.T) {
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if err := s.Save(ctx, "peer1", []byte("hello")); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, err := s.Load(ctx, "peer1")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if string(got) != "hello" {
				t.Fatalf("Load = %q, want %q", got, "hello")
			}
		})
	}
}

func TestStoreLoadMissingKeyReturnsNilNil(t *testing.T) {
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			got, err := s.Load(ctx, "does-not-exist")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got != nil {
				t.Fatalf("Load(missing) = %v, want nil", got)
			}
		})
	}
}

func TestStoreOverwrite(t *testing.T) {
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s.Save(ctx, "k", []byte("first"))
			s.Save(ctx, "k", []byte("second"))
			got, _ := s.Load(ctx, "k")
			if string(got) != "second" {
				t.Fatalf("Load after overwrite = %q, want %q", got, "second")
			}
		})
	}
}

func TestStoreDelete(t *testing.T) {
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s.Save(ctx, "k", []byte("v"))
			if err := s.Delete(ctx, "k"); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			got, err := s.Load(ctx, "k")
			if err != nil {
				t.Fatalf("Load after delete: %v", err)
			}
			if got != nil {
				t.Fatalf("Load after delete = %v, want nil", got)
			}
		})
	}
}

func TestStoreDeleteMissingKeyIsNotAnError(t *testing.T) {
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := s.Delete(context.Background(), "never-existed"); err != nil {
				t.Fatalf("Delete(missing): %v", err)
			}
		})
	}
}

func TestFileStoreKeysWithSpecialCharsAreSafe(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	ctx := context.Background()
	// A ControlAddr-shaped key: contains ':' and '.', which must not be
	// interpreted as path separators or otherwise break the filesystem
	// layout.
	key := "203.0.113.1:41820"
	if err := fs.Save(ctx, key, []byte("data")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := fs.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "data" {
		t.Fatalf("Load = %q, want %q", got, "data")
	}
}

func TestFileStorePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	fs1, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := fs1.Save(ctx, "peer", []byte("survives restart")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	fs2, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore (second instance): %v", err)
	}
	got, err := fs2.Load(ctx, "peer")
	if err != nil {
		t.Fatalf("Load from second instance: %v", err)
	}
	if string(got) != "survives restart" {
		t.Fatalf("Load from second instance = %q, want %q", got, "survives restart")
	}
}

func TestFileStoreSaveIsAtomicNoTempFileLeftBehind(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if err := fs.Save(context.Background(), "k", []byte("v")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file %q left behind after successful Save", e.Name())
		}
	}
}

func TestNewFileStoreCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "store")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("precondition: %s should not exist yet", dir)
	}
	if _, err := NewFileStore(dir); err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("NewFileStore did not create %s", dir)
	}
}
