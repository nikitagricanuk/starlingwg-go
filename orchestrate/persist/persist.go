// Package persist provides durable storage for the state a Session needs
// to resume gracefully after a process restart (last known working mode,
// endpoint info) -- since some platforms (notably iOS) may suspend or
// terminate the process running this logic without warning. What "durable"
// means differs by platform (a file on a server, an app-group container on
// iOS), so this is an injected interface, not a hardcoded file path.
package persist

import "context"

// Store persists small, named blobs. Implementations must be safe for
// concurrent use.
type Store interface {
	Save(ctx context.Context, key string, data []byte) error
	// Load returns (nil, nil) if key has never been saved -- not an error.
	Load(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}
