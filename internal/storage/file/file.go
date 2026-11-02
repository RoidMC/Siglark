// Package file provides a durable JSON-snapshot Store. It keeps the whole
// registry in one file and rewrites it atomically after every mutation. It is
// intended for single-node deployments and integration tests; heavier
// installations can add another Store implementation without touching nxs.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/roidmc/siglark/internal/nxs"
)

// Store persists challenges and registrations in a single JSON file.
type Store struct {
	mu            sync.RWMutex
	path          string
	challenges    map[string]*storedChallenge
	registrations map[string]*nxs.Registration
}

type snapshot struct {
	Challenges    []*storedChallenge  `json:"challenges"`
	Registrations []*nxs.Registration `json:"registrations"`
}

// storedChallenge mirrors nxs.Challenge plus the members the wire shape keeps
// out of JSON.
type storedChallenge struct {
	Protocol      string                      `json:"protocol"`
	Signature     string                      `json:"signature"`
	ChallengeID   string                      `json:"challengeId"`
	Nonce         string                      `json:"nonce"`
	Audience      string                      `json:"audience"`
	Thumbprint    string                      `json:"thumbprint"`
	Context       nxs.ChallengeContext        `json:"context"`
	ContextDigest string                      `json:"contextDigest"`
	ExpiresAt     int64                       `json:"expiresAt"`
	ServerTime    int64                       `json:"serverTime"`
	PoW           nxs.ProofOfWork             `json:"pow"`
	Authorization *nxs.ChallengeAuthorization `json:"authorization,omitempty"`
	PublicKeyJWK  nxs.PublicJWK               `json:"publicKeyJwk"`
	Used          bool                        `json:"used"`
	CompletedID   string                      `json:"completedId,omitempty"`
}

func newStoredChallenge(c *nxs.Challenge) *storedChallenge {
	return &storedChallenge{
		Protocol:      c.Protocol,
		Signature:     c.Signature,
		ChallengeID:   c.ChallengeID,
		Nonce:         c.Nonce,
		Audience:      c.Audience,
		Thumbprint:    c.Thumbprint,
		Context:       c.Context,
		ContextDigest: c.ContextDigest,
		ExpiresAt:     c.ExpiresAt,
		ServerTime:    c.ServerTime,
		PoW:           c.PoW,
		Authorization: c.Authorization,
		PublicKeyJWK:  c.PublicKeyJWK,
		Used:          c.Used,
		CompletedID:   c.CompletedID,
	}
}

func (s *storedChallenge) toChallenge() *nxs.Challenge {
	c := &nxs.Challenge{
		Protocol:      s.Protocol,
		Signature:     s.Signature,
		ChallengeID:   s.ChallengeID,
		Nonce:         s.Nonce,
		Audience:      s.Audience,
		Thumbprint:    s.Thumbprint,
		Context:       s.Context,
		ContextDigest: s.ContextDigest,
		ExpiresAt:     s.ExpiresAt,
		ServerTime:    s.ServerTime,
		PoW:           s.PoW,
		PublicKeyJWK:  s.PublicKeyJWK,
		Used:          s.Used,
		CompletedID:   s.CompletedID,
	}
	if s.Authorization != nil {
		auth := *s.Authorization
		c.Authorization = &auth
	}
	return c
}

// New opens or creates a store at path. An existing snapshot is validated and
// loaded before any traffic is served.
func New(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("file store: path is required")
	}
	s := &Store{
		path:          path,
		challenges:    map[string]*storedChallenge{},
		registrations: map[string]*nxs.Registration{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("file store: read %s: %w", s.path, err)
	}
	if len(data) == 0 {
		return nil
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("file store: decode %s: %w", s.path, err)
	}
	for _, c := range snap.Challenges {
		if c == nil || c.ChallengeID == "" {
			continue
		}
		s.challenges[c.ChallengeID] = c
	}
	for _, reg := range snap.Registrations {
		if reg == nil || reg.RegistrationID == "" {
			continue
		}
		normalize(reg)
		s.registrations[reg.RegistrationID] = reg
	}
	return nil
}

// normalize restores non-nil collections so later writes cannot panic.
func normalize(reg *nxs.Registration) {
	if reg.Records == nil {
		reg.Records = map[string]nxs.RecordedResponse{}
	}
	if reg.AdmissionKeys == nil {
		reg.AdmissionKeys = map[string]*nxs.AdmissionEpoch{}
	}
	if reg.AdmissionRequests == nil {
		reg.AdmissionRequests = map[string]string{}
	}
}

// persist rewrites the snapshot atomically. The caller holds the write lock.
func (s *Store) persist() error {
	snap := snapshot{
		Challenges:    make([]*storedChallenge, 0, len(s.challenges)),
		Registrations: make([]*nxs.Registration, 0, len(s.registrations)),
	}
	for _, c := range s.challenges {
		snap.Challenges = append(snap.Challenges, c)
	}
	for _, reg := range s.registrations {
		snap.Registrations = append(snap.Registrations, reg)
	}
	data, err := json.Marshal(&snap)
	if err != nil {
		return fmt.Errorf("file store: encode: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("file store: create directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".siglark-*.tmp")
	if err != nil {
		return fmt.Errorf("file store: create temp file: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("file store: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("file store: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("file store: close: %w", err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("file store: replace: %w", err)
	}
	return nil
}

// Close is a no-op; every mutation already persisted. It exists so callers can
// treat all stores uniformly.
func (s *Store) Close() error { return nil }

// Health checks that the snapshot path can be written.
func (s *Store) Health(context.Context) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".siglark-health-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// PutChallenge stores a copy of the challenge.
func (s *Store) PutChallenge(_ context.Context, c *nxs.Challenge) error {
	cp := newStoredChallenge(c)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[c.ChallengeID] = cp
	return s.persist()
}

// GetChallenge returns a copy of the stored challenge.
func (s *Store) GetChallenge(_ context.Context, id string) (*nxs.Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.challenges[id]
	if !ok {
		return nil, nxs.ErrNotFound
	}
	return c.toChallenge(), nil
}

// CompleteChallenge consumes the challenge and saves the registration returned
// by fn atomically.
func (s *Store) CompleteChallenge(_ context.Context, challengeID string, fn func(*nxs.Challenge, *nxs.Registration) (*nxs.Registration, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.challenges[challengeID]
	if !ok {
		return nxs.ErrNotFound
	}
	if stored.Used {
		return nxs.ErrChallengeUsed
	}
	var existing *nxs.Registration
	if stored.Context.RegistrationID != "" {
		if reg, ok := s.registrations[stored.Context.RegistrationID]; ok {
			existing = reg.Clone()
		}
	}
	challenge := stored.toChallenge()
	reg, err := fn(challenge, existing)
	if err != nil {
		return err
	}
	if reg == nil {
		return nxs.ErrNotFound
	}
	normalize(reg)
	stored.Used = true
	stored.CompletedID = reg.RegistrationID
	s.registrations[reg.RegistrationID] = reg
	return s.persist()
}

// GetRegistration returns a copy of the stored registration.
func (s *Store) GetRegistration(_ context.Context, id string) (*nxs.Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	reg, ok := s.registrations[id]
	if !ok {
		return nil, nxs.ErrNotFound
	}
	return reg.Clone(), nil
}

// GetRegistrationByInstance resolves a registration by its runtime instance ID.
func (s *Store) GetRegistrationByInstance(_ context.Context, instanceID string) (*nxs.Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, reg := range s.registrations {
		if reg.InstanceID == instanceID {
			return reg.Clone(), nil
		}
	}
	return nil, nxs.ErrNotFound
}

// ListRegistrations returns copies of every stored registration.
func (s *Store) ListRegistrations(_ context.Context) ([]*nxs.Registration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*nxs.Registration, 0, len(s.registrations))
	for _, reg := range s.registrations {
		out = append(out, reg.Clone())
	}
	return out, nil
}

// UpdateRegistration commits the callback's changes only when it succeeds.
func (s *Store) UpdateRegistration(_ context.Context, id string, fn func(*nxs.Registration) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, ok := s.registrations[id]
	if !ok {
		return nxs.ErrNotFound
	}
	cp := reg.Clone()
	if err := fn(cp); err != nil {
		return err
	}
	normalize(cp)
	s.registrations[id] = cp
	return s.persist()
}

// DeleteRegistration removes a registration permanently.
func (s *Store) DeleteRegistration(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.registrations[id]; !ok {
		return nxs.ErrNotFound
	}
	delete(s.registrations, id)
	return s.persist()
}
