package orchestrate

import (
	"context"
	"encoding/json"
	"time"
)

// persistedSession is the on-disk (or in-memory) record of a Y session's
// last-known mode, per Config.Store's doc. Keyed by the same string
// Orchestrator.sessions itself uses (a Y's PeerConfig.ControlAddr).
type persistedSession struct {
	LastMode         string `json:"last_mode"` // "native" or "cloaked"
	LastExternalAddr string `json:"last_external_addr,omitempty"`
	LastSuccessUnix  int64  `json:"last_success_unix"`
}

// saveSession records key's last-known mode, if a Store is configured.
// Best-effort: a failed save only costs a future cold re-probe, not
// correctness, so it's logged rather than propagated.
func (o *Orchestrator) saveSession(key, mode, externalAddr string) {
	if o.cfg.Store == nil {
		return
	}
	data, err := json.Marshal(persistedSession{
		LastMode:         mode,
		LastExternalAddr: externalAddr,
		LastSuccessUnix:  time.Now().Unix(),
	})
	if err != nil {
		return
	}
	if err := o.cfg.Store.Save(context.Background(), key, data); err != nil {
		o.cfg.Logger.Errorf("orchestrate: persist session state for %s: %v", key, err)
	}
}

// loadSession returns key's persisted record, if a Store is configured
// and a record exists.
func (o *Orchestrator) loadSession(key string) (*persistedSession, bool) {
	if o.cfg.Store == nil {
		return nil, false
	}
	data, err := o.cfg.Store.Load(context.Background(), key)
	if err != nil || data == nil {
		return nil, false
	}
	var rec persistedSession
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}
