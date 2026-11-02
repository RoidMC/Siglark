// Package memory provides the default in-process Store implementation. It is
// intended for development, tests and single-node MVP deployments.
package memory

import (
	"context"
	"sync"

	"github.com/roidmc/siglark/internal/nxs"
)

// Store keeps challenges and registrations in memory with a single mutex.
type Store struct {
	mu            sync.RWMutex
	challenges    map[string]*nxs.Challenge
	registrations map[string]*nxs.Registration
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		challenges:    map[string]*nxs.Challenge{},
		registrations: map[string]*nxs.Registration{},
	}
}

// Health always succeeds for the in-process store.
func (s *Store) Health(context.Context) error { return nil }

// PutChallenge stores a copy of the challenge.
func (s *Store) PutChallenge(_ context.Context, c *nxs.Challenge) error {
	cp := *c
	if c.Authorization != nil {
		auth := *c.Authorization
		cp.Authorization = &auth
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[c.ChallengeID] = &cp
	return nil
}

// GetChallenge returns a copy of the stored challenge.
func (s *Store) GetChallenge(_ context.Context, id string) (*nxs.Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.challenges[id]
	if !ok {
		return nil, nxs.ErrNotFound
	}
	cp := *c
	if c.Authorization != nil {
		auth := *c.Authorization
		cp.Authorization = &auth
	}
	return &cp, nil
}

// CompleteChallenge consumes the challenge and saves the registration.
func (s *Store) CompleteChallenge(_ context.Context, challengeID string, fn func(*nxs.Challenge, *nxs.Registration) (*nxs.Registration, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[challengeID]
	if !ok {
		return nxs.ErrNotFound
	}
	if c.Used {
		return nxs.ErrChallengeUsed
	}
	var existing *nxs.Registration
	if c.Context.RegistrationID != "" {
		if reg, ok := s.registrations[c.Context.RegistrationID]; ok {
			existing = reg.Clone()
		}
	}
	reg, err := fn(c, existing)
	if err != nil {
		return err
	}
	if reg == nil {
		return nxs.ErrNotFound
	}
	c.Used = true
	c.CompletedID = reg.RegistrationID
	s.registrations[reg.RegistrationID] = reg
	return nil
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
	s.registrations[id] = cp
	return nil
}

// DeleteRegistration removes a registration permanently.
func (s *Store) DeleteRegistration(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.registrations[id]; !ok {
		return nxs.ErrNotFound
	}
	delete(s.registrations, id)
	return nil
}
