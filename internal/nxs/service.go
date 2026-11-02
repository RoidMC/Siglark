package nxs

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// bearerRecord is one authorization record. The credential itself is never
// retained; only a SHA-256 digest used for lookup.
type bearerRecord struct {
	Reference string
	TokenHash string
	Label     string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// Service is the embedded NXS provider. It implements Provider on top of a
// pluggable Store.
type Service struct {
	store    Store
	origin   string
	opts     Options
	now      func() time.Time
	hosts    map[string]string
	hostsMu  sync.RWMutex
	verifier *IdentityVerifier

	tokensMu sync.RWMutex
	bearer   map[string]string // SHA-256 hex of token -> opaque authorization reference
	tokens   map[string]*bearerRecord
}

// NewService validates options and builds the provider.
func NewService(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("nxs: Store is required")
	}
	if err := ValidateOrigin(opts.Origin); err != nil {
		return nil, fmt.Errorf("nxs: provider origin: %w", err)
	}
	if opts.ProofOfWorkDifficulty < 0 || opts.ProofOfWorkDifficulty > 24 {
		return nil, fmt.Errorf("nxs: proof-of-work difficulty must be 0..24")
	}
	if opts.ChallengeTTL <= 0 {
		opts.ChallengeTTL = 5 * time.Minute
	}
	if opts.HeartbeatIntervalMs <= 0 {
		opts.HeartbeatIntervalMs = 10000
	}
	if opts.LeaseMillis <= 0 {
		opts.LeaseMillis = opts.HeartbeatIntervalMs + 60000
	}
	if opts.MinUpdateIntervalMs <= 0 {
		opts.MinUpdateIntervalMs = 1000
	}
	if opts.OldKeyRetireAfter <= 0 {
		opts.OldKeyRetireAfter = 24 * time.Hour
	}
	if opts.RegistrationRetention <= 0 {
		opts.RegistrationRetention = 24 * time.Hour
	}
	if opts.AdmissionTTL <= 0 {
		opts.AdmissionTTL = 60 * time.Second
	}
	if max := time.Duration(MaxAdmissionTTLSkewSeconds) * time.Second; opts.AdmissionTTL > max {
		opts.AdmissionTTL = max
	}
	if opts.AssistedJoinTimeout <= 0 {
		opts.AssistedJoinTimeout = 30 * time.Second
	}
	if opts.AssistedJoinTimeout > 30*time.Second {
		opts.AssistedJoinTimeout = 30 * time.Second
	}
	hosts := make(map[string]string, len(opts.HostMappings))
	for host, registrationID := range opts.HostMappings {
		if key := normalizeHost(host); key != "" {
			hosts[key] = registrationID
		}
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	bearer := make(map[string]string, len(opts.BearerTokens))
	tokens := make(map[string]*bearerRecord, len(opts.BearerTokens))
	now := clock()
	for _, token := range opts.BearerTokens {
		if token == "" {
			continue
		}
		digest := tokenDigest(token)
		ref := "auth_" + digest[:16]
		if _, exists := tokens[ref]; exists {
			continue
		}
		bearer[digest] = ref
		tokens[ref] = &bearerRecord{Reference: ref, TokenHash: digest, Label: "config", CreatedAt: now}
	}
	return &Service{
		store: opts.Store, origin: opts.Origin, opts: opts,
		hosts: hosts, verifier: NewIdentityVerifier(IdentityTrust(opts.IdentityTrust)),
		bearer: bearer, tokens: tokens, now: clock,
	}, nil
}

// Name identifies the embedded backend.
func (s *Service) Name() string { return "embedded" }

// Discovery returns the v1 discovery document.
func (s *Service) Discovery() *DiscoveryDocument {
	schemes := []string{"anonymous-proof-of-work"}
	if s.activeBearerCount() > 0 {
		schemes = append(schemes, "bearer-token")
	}
	doc := &DiscoveryDocument{
		Provider:   s.origin,
		Protocols:  []string{Protocol},
		Signatures: []string{SignatureVersion},
		Authorization: DiscoveryAuthorization{
			Schemes: schemes,
		},
		Limits: DiscoveryLimits{
			HeartbeatIntervalMs: int(s.opts.HeartbeatIntervalMs),
		},
	}
	if s.opts.WebSocketControl {
		doc.Extensions = map[string]any{
			extensionWebSocket: map[string]any{
				"version":  1,
				"critical": false,
				"data":     map[string]any{},
			},
		}
	}
	return doc
}

// Register issues an enrollment, attach or recovery challenge.
func (s *Service) Register(ctx context.Context, req *RegisterRequest) (*Challenge, error) {
	if req == nil || req.Protocol != Protocol {
		return nil, errInvalidRequest("protocol must be " + Protocol)
	}
	now := s.now()
	var (
		key      *PublicJWK
		mode     string
		authID   string
		service  string
		regID    string
		label    string
		diff     int
		authWire *ChallengeAuthorization
	)
	if req.RegistrationID != "" {
		if !validID(req.RegistrationID) {
			return nil, errInvalidRequest("registrationId is malformed")
		}
		reg, err := s.store.GetRegistration(ctx, req.RegistrationID)
		if err != nil {
			return nil, ErrRecoveryUnavailable
		}
		active, ok := reg.ActiveKey()
		if !ok {
			return nil, ErrRecoveryUnavailable
		}
		k := active.JWK()
		key = &k
		mode = "recover"
		service = reg.ServiceID
		regID = reg.RegistrationID
	} else {
		if len(req.PublicKeyJWK) == 0 {
			return nil, errInvalidRequest("publicKeyJwk is required")
		}
		var pub *ecdsa.PublicKey
		var err error
		key, pub, err = ParsePublicJWK(req.PublicKeyJWK)
		if err != nil {
			return nil, errInvalidRequest(err.Error())
		}
		_ = pub
		if req.Label != nil {
			if err := validateDisplayText(*req.Label, 128); err != nil {
				return nil, errInvalidRequest("label " + err.Error())
			}
			label = *req.Label
		}
		if req.BearerToken != "" {
			ref, ok := s.bearerReference(req.BearerToken)
			if !ok {
				return nil, NewError(http.StatusUnauthorized, "invalid_token", "The bearer token is not accepted.")
			}
			mode = "attach-instance"
			authID = ref
			service = "svc_" + strings.TrimPrefix(ref, "auth_")[:16]
			authWire = &ChallengeAuthorization{Scheme: "bearer-token", Reference: ref}
		} else {
			mode = "new-service"
			diff = s.opts.ProofOfWorkDifficulty
		}
	}

	cctx := ChallengeContext{
		Mode:            mode,
		Label:           label,
		AuthorizationID: authID,
		ServiceID:       service,
		RegistrationID:  regID,
	}
	ch := &Challenge{
		Protocol:      Protocol,
		Signature:     SignatureVersion,
		ChallengeID:   newID("ch"),
		Nonce:         randomURLToken(16),
		Audience:      s.origin,
		Thumbprint:    key.Thumbprint(),
		Context:       cctx,
		ContextDigest: ContextDigest(cctx),
		ExpiresAt:     now.Add(s.opts.ChallengeTTL).UnixMilli(),
		ServerTime:    now.UnixMilli(),
		PoW:           ProofOfWork{Difficulty: diff},
		Authorization: authWire,
		PublicKeyJWK:  *key,
	}
	if err := s.store.PutChallenge(ctx, ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// Complete validates the challenge proof and atomically starts a generation.
func (s *Service) Complete(ctx context.Context, req *CompletionRequest) (*RegistrationResponse, error) {
	if req == nil || req.Protocol != Protocol {
		return nil, errInvalidRequest("protocol must be " + Protocol)
	}
	if !validID(req.ChallengeID) {
		return nil, errInvalidRequest("challengeId is malformed")
	}
	if len(req.ProofNonce) < 1 || len(req.ProofNonce) > 128 {
		return nil, errInvalidRequest("proofNonce must be 1..128 characters")
	}
	if !validURLToken(req.IdempotencyKey, 16, 128) {
		return nil, errInvalidRequest("idempotencyKey must be 16..128 URL-safe characters")
	}

	ch, err := s.store.GetChallenge(ctx, req.ChallengeID)
	if err != nil {
		if err == ErrNotFound {
			return nil, ErrRecoveryUnavailable
		}
		return nil, err
	}
	if ch.Used {
		return nil, ErrRecoveryRequired
	}
	nowMs := s.now().UnixMilli()
	if nowMs >= ch.ExpiresAt {
		return nil, errChallengeExpired()
	}
	pub, err := parseJWK(ch.PublicKeyJWK)
	if err != nil {
		return nil, err
	}
	payload := CompleteProofPayload(
		ch.Audience, ch.ChallengeID, ch.Nonce, ch.Thumbprint, ch.ContextDigest,
		ch.ExpiresAt, req.ProofNonce, req.IdempotencyKey,
	)
	if err := VerifyES384(pub, payload, req.Signature); err != nil {
		return nil, errInvalidSignature("The completion signature is invalid.")
	}
	if LeadingZeroBits(payload) < ch.PoW.Difficulty {
		return nil, errInsufficientPoW()
	}

	var (
		resp       *RegistrationResponse
		oneTimeKey *AdmissionKey
	)
	err = s.store.CompleteChallenge(ctx, ch.ChallengeID, func(c *Challenge, existing *Registration) (*Registration, error) {
		var reg *Registration
		switch c.Context.Mode {
		case "new-service", "attach-instance":
			reg = s.newRegistration(c, nowMs)
			epoch, secret, err := newAdmissionEpoch(reg)
			if err != nil {
				return nil, err
			}
			reg.AdmissionKeys[epoch.KeyID] = epoch
			reg.ActiveAdmissionKeyID = epoch.KeyID
			oneTimeKey = &AdmissionKey{KeyID: epoch.KeyID, Secret: secret}
		case "recover":
			if existing == nil || !existing.IsCurrentKeyThumbprint(c.Thumbprint) {
				return nil, ErrRecoveryUnavailable
			}
			reg = existing.Clone()
			reg.LeaseGeneration++
			reg.LastSequence = 0
			reg.Records = map[string]RecordedResponse{}
			reg.RecordOrder = nil
			reg.AcceptingPlayers = false
			reg.ConnectedPlayers = ConnectedPlayers{}
			reg.ProfileRevision = ""
			reg.ProfileJSON = nil
			reg.ServerStatus = nil
			reg.Software = nil
			reg.BedrockProtocols = nil
			reg.LastHeartbeatAt = time.Time{}
			reg.UpdatedAt = time.UnixMilli(nowMs)
		default:
			return nil, errInvalidRequest("unknown challenge mode")
		}
		c.Used = true
		c.CompletedID = reg.RegistrationID
		resp = &RegistrationResponse{
			Protocol:        Protocol,
			Provider:        s.origin,
			RegistrationID:  reg.RegistrationID,
			InstanceID:      reg.InstanceID,
			KeyID:           reg.ActiveKeyID,
			LeaseGeneration: reg.LeaseGeneration,
		}
		return reg, nil
	})
	if err != nil {
		if err == ErrChallengeUsed {
			return nil, ErrRecoveryRequired
		}
		return nil, err
	}
	if oneTimeKey != nil {
		resp.AdmissionKey = oneTimeKey
	}
	return resp, nil
}

func (s *Service) newRegistration(c *Challenge, nowMs int64) *Registration {
	now := time.UnixMilli(nowMs)
	serviceID := c.Context.ServiceID
	if serviceID == "" {
		serviceID = "svc_" + randomHex(16)
	}
	keyID := newID("key")
	return &Registration{
		RegistrationID:  newID("reg"),
		InstanceID:      newID("inst"),
		ServiceID:       serviceID,
		Label:           c.Context.Label,
		LeaseGeneration: 1,
		Keys: []MachineKey{{
			KeyID:      keyID,
			X:          c.PublicKeyJWK.X,
			Y:          c.PublicKeyJWK.Y,
			Thumbprint: c.Thumbprint,
			CreatedAt:  now,
		}},
		ActiveKeyID:       keyID,
		Records:           map[string]RecordedResponse{},
		AdmissionKeys:     map[string]*AdmissionEpoch{},
		AdmissionRequests: map[string]string{},
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

func newAdmissionEpoch(reg *Registration) (*AdmissionEpoch, string, error) {
	keyID, err := newAdmissionKeyID(reg.AdmissionKeys)
	if err != nil {
		return nil, "", err
	}
	secretRaw := make([]byte, 32)
	if _, err := rand.Read(secretRaw); err != nil {
		return nil, "", err
	}
	secret := Base64URL(secretRaw)
	return &AdmissionEpoch{KeyID: keyID, Secret: secret, CreatedAt: reg.CreatedAt}, secret, nil
}

// Heartbeat applies a signed heartbeat and returns the recorded response.
func (s *Service) Heartbeat(ctx context.Context, req *SignedRequest, body *HeartbeatRequest) (json.RawMessage, error) {
	if body == nil {
		return nil, errInvalidRequest("body is required")
	}
	return s.applySigned(ctx, req, func(r *Registration) (any, error) {
		return s.applyHeartbeat(ctx, r, body, req.Timestamp)
	})
}

// Outcomes stores signed transport/game observations.
func (s *Service) Outcomes(ctx context.Context, req *SignedRequest, body *OutcomesRequest) (json.RawMessage, error) {
	if body == nil {
		return nil, errInvalidRequest("body is required")
	}
	if len(body.Events) < 1 || len(body.Events) > 100 {
		return nil, errInvalidRequest("events must contain 1..100 items")
	}
	for _, ev := range body.Events {
		if len(ev.TicketID) != 32 || !isLowerHex(ev.TicketID) {
			return nil, errInvalidRequest("ticketId must be 32 lowercase hex characters")
		}
		if ev.Stage == "" || len(ev.Stage) > 128 {
			return nil, errInvalidRequest("stage is malformed")
		}
		if ev.OccurredAt < 0 {
			return nil, errInvalidRequest("occurredAt is malformed")
		}
		if ev.Reason != nil && len(*ev.Reason) > 128 {
			return nil, errInvalidRequest("reason is too long")
		}
	}
	return s.applySigned(ctx, req, func(r *Registration) (any, error) {
		for _, ev := range body.Events {
			rec := OutcomeRecord{TicketID: ev.TicketID, Stage: ev.Stage, OccurredAt: ev.OccurredAt}
			if ev.Reason != nil {
				rec.Reason = *ev.Reason
			}
			r.Outcomes = append(r.Outcomes, rec)
		}
		if len(r.Outcomes) > 4096 {
			r.Outcomes = r.Outcomes[len(r.Outcomes)-4096:]
		}
		return EmptyResponse{}, nil
	})
}

// Rotate installs a replacement machine signing key.
func (s *Service) Rotate(ctx context.Context, req *SignedRequest, body *RotationRequest) (json.RawMessage, error) {
	if body == nil {
		return nil, errInvalidRequest("body is required")
	}
	newKey, newPub, err := ParsePublicJWK(body.PublicKeyJWK)
	if err != nil {
		return nil, errInvalidRequest(err.Error())
	}
	proof := RotateProofPayload(s.origin, req.InstanceID, req.KeyID, newKey.Thumbprint(), req.Generation, req.IdempotencyKey)
	if err := VerifyES384(newPub, proof, body.Proof); err != nil {
		return nil, errInvalidSignature("The rotation proof is invalid.")
	}
	return s.applySigned(ctx, req, func(r *Registration) (any, error) {
		for _, k := range r.Keys {
			if k.Thumbprint == newKey.Thumbprint() && k.RetiredAt == nil {
				return nil, errInvalidRequest("replacement key is already installed")
			}
		}
		keyID := newID("key")
		now := s.now()
		retireAt := now.Add(s.opts.OldKeyRetireAfter)
		for i := range r.Keys {
			if r.Keys[i].KeyID == r.ActiveKeyID && r.Keys[i].RetiredAt == nil {
				r.Keys[i].RetireAt = &retireAt
			}
		}
		r.Keys = append(r.Keys, MachineKey{
			KeyID: keyID, X: newKey.X, Y: newKey.Y,
			Thumbprint: newKey.Thumbprint(), CreatedAt: now,
		})
		r.ActiveKeyID = keyID
		return RotationResponse{KeyID: keyID, OldKeyRetiresAt: retireAt.UnixMilli()}, nil
	})
}

// Retire ends another machine key immediately.
func (s *Service) Retire(ctx context.Context, req *SignedRequest, body *RetireRequest) (json.RawMessage, error) {
	if body == nil || !validID(body.KeyID) {
		return nil, errInvalidRequest("keyId is required")
	}
	if body.KeyID == req.KeyID {
		return nil, errInvalidRequest("the request key cannot retire itself")
	}
	return s.applySigned(ctx, req, func(r *Registration) (any, error) {
		for i := range r.Keys {
			if r.Keys[i].KeyID != body.KeyID {
				continue
			}
			if r.Keys[i].RetiredAt != nil {
				return EmptyResponse{}, nil
			}
			now := s.now()
			r.Keys[i].RetiredAt = &now
			return EmptyResponse{}, nil
		}
		return nil, errInvalidRequest("unknown keyId")
	})
}

// Deregister permanently ends the registration.
func (s *Service) Deregister(ctx context.Context, req *SignedRequest) (json.RawMessage, error) {
	reg, err := s.authenticate(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.store.DeleteRegistration(ctx, reg.RegistrationID); err != nil {
		return nil, err
	}
	return json.RawMessage(`{}`), nil
}

// OperatorAction returns an operator link when the provider offers one.
func (s *Service) OperatorAction(ctx context.Context, req *SignedRequest) (json.RawMessage, error) {
	return s.applySigned(ctx, req, func(r *Registration) (any, error) {
		return map[string]any{}, nil
	})
}

func (s *Service) applySigned(ctx context.Context, req *SignedRequest, apply func(*Registration) (any, error)) (json.RawMessage, error) {
	if req == nil {
		return nil, errInvalidRequest("signed request is required")
	}
	if !validURLToken(req.IdempotencyKey, 16, 128) {
		return nil, errInvalidRequest("idempotency-key header is malformed")
	}
	reg, err := s.authenticate(ctx, req)
	if err != nil {
		return nil, err
	}

	var out json.RawMessage
	bodyHash := BodySHA256(req.Body)
	err = s.store.UpdateRegistration(ctx, reg.RegistrationID, func(r *Registration) error {
		if rec, ok := r.Records[req.IdempotencyKey]; ok {
			if rec.BodySHA256 != bodyHash {
				return NewError(http.StatusBadRequest, "idempotency_conflict", "The idempotency key was used with a different body.")
			}
			out = rec.Response
			return nil
		}
		if req.Sequence <= r.LastSequence {
			return NewError(http.StatusConflict, "sequence_replay", "The request sequence was not above the last accepted sequence.")
		}
		r.LastSequence = req.Sequence
		result, err := apply(r)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		r.Records[req.IdempotencyKey] = RecordedResponse{BodySHA256: bodyHash, Response: encoded}
		r.RecordOrder = append(r.RecordOrder, req.IdempotencyKey)
		for len(r.RecordOrder) > 128 {
			oldest := r.RecordOrder[0]
			r.RecordOrder = r.RecordOrder[1:]
			delete(r.Records, oldest)
		}
		r.UpdatedAt = s.now()
		out = encoded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) authenticate(ctx context.Context, req *SignedRequest) (*Registration, error) {
	if req == nil || req.InstanceID == "" || req.KeyID == "" || req.Signature == "" {
		return nil, errInvalidSignature("required NXS request headers are missing")
	}
	if req.Timestamp <= 0 || req.Generation <= 0 || req.Sequence <= 0 {
		return nil, errInvalidRequest("signed request headers are malformed")
	}
	nowMs := s.now().UnixMilli()
	if req.Timestamp > nowMs+MaxClockSkewSeconds*1000 || req.Timestamp < nowMs-MaxClockSkewSeconds*1000 {
		return nil, NewError(http.StatusUnauthorized, "stale_request", "The request timestamp is outside the accepted window.")
	}
	reg, err := s.store.GetRegistrationByInstance(ctx, req.InstanceID)
	if err != nil {
		return nil, errUnknownRegistration()
	}
	if req.Generation != reg.LeaseGeneration {
		return nil, ErrGenerationFenced
	}
	mk, ok := reg.KeyByID(req.KeyID)
	if !ok {
		return nil, NewError(http.StatusUnauthorized, "unknown_key", "The signing key is unknown or retired.")
	}
	if mk.RetiredAt != nil || (mk.RetireAt != nil && !s.now().Before(*mk.RetireAt)) {
		return nil, NewError(http.StatusUnauthorized, "unknown_key", "The signing key is unknown or retired.")
	}
	pub, err := parseJWK(mk.JWK())
	if err != nil {
		return nil, err
	}
	payload := RequestPayload(s.origin, req.Method, req.Path, req.Timestamp, req.InstanceID, req.KeyID, req.IdempotencyKey, req.Generation, req.Sequence, req.Body)
	if err := VerifyES384(pub, payload, req.Signature); err != nil {
		return nil, errInvalidSignature("The request signature is invalid.")
	}
	return reg, nil
}

func (s *Service) applyHeartbeat(ctx context.Context, r *Registration, body *HeartbeatRequest, timestamp int64) (any, error) {
	if body.AcceptingPlayers == nil || body.Capacity == nil || body.ConnectedPlayers == nil {
		return nil, errInvalidRequest("acceptingPlayers, capacity and connectedPlayers are required")
	}
	now := s.now()
	// Early heartbeats are only for listing and player-count updates. Changes
	// to acceptance, the profile or admission-key acknowledgements are sent at
	// once and are never throttled.
	if !heartbeatIsUrgent(r, body) && !r.LastHeartbeatAt.IsZero() {
		earliest := r.LastHeartbeatAt.Add(time.Duration(s.opts.MinUpdateIntervalMs) * time.Millisecond)
		if now.Before(earliest) {
			retry := int((earliest.Sub(now) + time.Second - 1) / time.Second)
			if retry < 1 {
				retry = 1
			}
			return nil, &Error{
				Code:       "rate_limited",
				Status:     http.StatusTooManyRequests,
				Message:    "Heartbeats are arriving faster than the provider allows.",
				RetryAfter: retry,
			}
		}
	}
	if *body.Capacity < 0 || *body.Capacity > 1000000 {
		return nil, errInvalidRequest("capacity is out of range")
	}
	cp := body.ConnectedPlayers
	if cp.Count < 0 || cp.Count > 1000000 {
		return nil, errInvalidRequest("connectedPlayers.count is out of range")
	}
	if cp.SampledAt < 0 || cp.SampledAt > timestamp {
		return nil, errInvalidRequest("connectedPlayers.sampledAt must not be after the request timestamp")
	}
	if body.ServerStatus != nil {
		if body.ServerStatus.Name == "" || len(body.ServerStatus.Name) > 128 || validateDisplayText(body.ServerStatus.Name, 128) != nil {
			return nil, errInvalidRequest("serverStatus.name is malformed")
		}
		if len(body.ServerStatus.Level) > 128 || validateDisplayText(body.ServerStatus.Level, 128) != nil {
			return nil, errInvalidRequest("serverStatus.level is malformed")
		}
		if body.ServerStatus.MaxPlayerCount < 0 || body.ServerStatus.MaxPlayerCount > 1000000 {
			return nil, errInvalidRequest("serverStatus.maxPlayerCount is out of range")
		}
		if body.ServerStatus.GameType < 0 || body.ServerStatus.GameType > 2 {
			return nil, errInvalidRequest("serverStatus.gameType is out of range")
		}
	}
	if body.Software != nil {
		if err := validateDisplayText(body.Software.Name, 64); err != nil || body.Software.Name == "" {
			return nil, errInvalidRequest("software.name is malformed")
		}
		if body.Software.Version == "" || validateDisplayText(body.Software.Version, 128) != nil {
			return nil, errInvalidRequest("software.version is malformed")
		}
	}
	if len(body.BedrockProtocols) > 0 {
		var protocols struct {
			Accepted []int  `json:"accepted"`
			Version  string `json:"version"`
		}
		if err := json.Unmarshal(body.BedrockProtocols, &protocols); err != nil || len(protocols.Accepted) < 1 ||
			len(protocols.Accepted) > 512 || protocols.Version == "" || validateDisplayText(protocols.Version, 64) != nil {
			return nil, errInvalidRequest("bedrockProtocols is malformed")
		}
		for i, n := range protocols.Accepted {
			if n < 1 || n > 2147483647 || (i > 0 && n <= protocols.Accepted[i-1]) {
				return nil, errInvalidRequest("bedrockProtocols.accepted must be strictly ascending protocol numbers")
			}
		}
	}

	r.AcceptingPlayers = *body.AcceptingPlayers
	r.Capacity = *body.Capacity
	r.ConnectedPlayers = *cp
	if body.ServerStatus != nil {
		status := *body.ServerStatus
		r.ServerStatus = &status
	}
	if body.Software != nil {
		software := *body.Software
		r.Software = &software
	}
	if len(body.BedrockProtocols) > 0 {
		if strings.TrimSpace(string(body.BedrockProtocols)) == "null" {
			r.BedrockProtocols = nil
		} else {
			r.BedrockProtocols = append(json.RawMessage(nil), body.BedrockProtocols...)
		}
	}

	// Install and acknowledge admission epochs before validating the profile.
	if len(body.InstalledAdmissionKeyIDs) > 0 {
		if len(body.InstalledAdmissionKeyIDs) > 8 {
			return nil, errInvalidRequest("installedAdmissionKeyIds has more than 8 entries")
		}
		seen := make(map[string]bool, len(body.InstalledAdmissionKeyIDs))
		for _, id := range body.InstalledAdmissionKeyIDs {
			if !validAdmissionKeyID(id) || seen[id] {
				return nil, errInvalidRequest("installedAdmissionKeyIds is malformed")
			}
			seen[id] = true
			epoch, ok := r.AdmissionKeys[id]
			if !ok {
				return nil, NewError(http.StatusBadRequest, "unknown_admission_key", "The host acknowledged an admission key the provider never issued.")
			}
			epoch.Acked = true
		}
		r.ActiveAdmissionKeyID = body.InstalledAdmissionKeyIDs[len(body.InstalledAdmissionKeyIDs)-1]
	}

	var profileRevision *string
	if body.HostProfile != nil {
		if err := validateHostProfile(body.HostProfile); err != nil {
			return nil, errInvalidRequest(err.Error())
		}
		encoded, err := json.Marshal(body.HostProfile)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(encoded)
		r.ProfileJSON = encoded
		r.ProfileRevision = "prof_" + Base64URL(sum[:])
		if body.HostProfile.StatelessAdmission != nil {
			r.Incarnation = body.HostProfile.StatelessAdmission.Incarnation
		}
		rev := r.ProfileRevision
		profileRevision = &rev
	} else if body.HostProfileRevision != nil {
		if *body.HostProfileRevision == r.ProfileRevision && r.ProfileRevision != "" {
			rev := r.ProfileRevision
			profileRevision = &rev
		}
	} else if r.ProfileRevision != "" {
		rev := r.ProfileRevision
		profileRevision = &rev
	}

	resp := &HeartbeatResponse{
		HostProfileRevision: profileRevision,
		CheckIn: CheckIn{
			AfterMillis:             s.opts.HeartbeatIntervalMs,
			LeaseMillis:             s.opts.LeaseMillis,
			MinUpdateIntervalMillis: s.opts.MinUpdateIntervalMs,
		},
		AdmissionKeyRetirements: []AdmissionKeyRetirement{},
	}

	if body.AdmissionKeyRequestID != nil {
		id := *body.AdmissionKeyRequestID
		if !validURLToken(id, 16, 128) {
			return nil, errInvalidRequest("admissionKeyRequestId is malformed")
		}
		if keyID, ok := r.AdmissionRequests[id]; ok {
			resp.AdmissionKeyRequest = &AdmissionKeyRequest{ID: id, KeyID: keyID}
		} else {
			if len(r.AdmissionKeys) >= 8 {
				return nil, NewError(http.StatusForbidden, "admission_key_limit", "The host already holds the maximum number of admission keys.")
			}
			epoch, secret, err := newAdmissionEpoch(r)
			if err != nil {
				return nil, err
			}
			r.AdmissionKeys[epoch.KeyID] = epoch
			r.ActiveAdmissionKeyID = epoch.KeyID
			r.AdmissionRequests[id] = epoch.KeyID
			resp.AdmissionKeyRequest = &AdmissionKeyRequest{ID: id, KeyID: epoch.KeyID}
			resp.AdmissionKey = &AdmissionKey{KeyID: epoch.KeyID, Secret: secret}
		}
	}

	r.LastHeartbeatAt = now
	resp.Readiness = s.readiness(r)
	return resp, nil
}

// heartbeatIsUrgent reports whether a heartbeat changes state that must be
// delivered immediately rather than on the normal schedule.
func heartbeatIsUrgent(r *Registration, body *HeartbeatRequest) bool {
	if body.AcceptingPlayers != nil && *body.AcceptingPlayers != r.AcceptingPlayers {
		return true
	}
	if body.HostProfile != nil {
		return true
	}
	if len(body.InstalledAdmissionKeyIDs) > 0 {
		return true
	}
	return body.AdmissionKeyRequestID != nil
}

// readiness computes the current routing observation for a registration.
func (s *Service) readiness(r *Registration) Readiness {
	reasons := []string{}
	if _, expired := s.leaseExpiredAt(r); expired {
		reasons = append(reasons, "lease_expired")
	}
	if len(r.ProfileJSON) == 0 {
		reasons = append(reasons, "profile_missing")
	}
	if !r.AcceptingPlayers {
		reasons = append(reasons, "players_paused")
	}
	if r.ActiveAdmissionKeyID == "" {
		reasons = append(reasons, "admission_key_missing")
	} else if epoch, ok := r.AdmissionKeys[r.ActiveAdmissionKeyID]; !ok || !epoch.Acked {
		reasons = append(reasons, "admission_key_unacknowledged")
	}
	if len(r.ProfileJSON) > 0 && r.ActiveAdmissionKeyID != "" {
		var p HostProfile
		if err := json.Unmarshal(r.ProfileJSON, &p); err == nil && p.AdmissionKeyID != r.ActiveAdmissionKeyID {
			reasons = append(reasons, "profile_key_mismatch")
		}
	}
	return Readiness{Routable: len(reasons) == 0, Reasons: reasons}
}

// leaseExpiredAt returns the instant a registration stops being routable.
func (s *Service) leaseExpiredAt(r *Registration) (time.Time, bool) {
	base := r.LastHeartbeatAt
	if base.IsZero() {
		base = r.CreatedAt
	}
	if base.IsZero() {
		return time.Time{}, false
	}
	deadline := base.Add(time.Duration(s.opts.LeaseMillis) * time.Millisecond)
	return deadline, !s.now().Before(deadline)
}

func validateHostProfile(p *HostProfile) error {
	if p == nil {
		return fmt.Errorf("hostProfile is required")
	}
	if len(p.Candidates) > 32 {
		return fmt.Errorf("hostProfile has more than 32 candidates")
	}
	if !strings.HasPrefix(p.DTLSFingerprint, "sha-256 ") || len(p.DTLSFingerprint) > 256 {
		return fmt.Errorf("hostProfile.dtlsFingerprint is malformed")
	}
	if !validAdmissionKeyID(p.AdmissionKeyID) {
		return fmt.Errorf("hostProfile.admissionKeyId is malformed")
	}
	if p.SctpPort < 1 || p.SctpPort > 65535 {
		return fmt.Errorf("hostProfile.sctpPort is out of range")
	}
	if p.MaxMessageSize < 1 || p.MaxMessageSize > 262144 {
		return fmt.Errorf("hostProfile.maxMessageSize is out of range")
	}
	if p.StatelessAdmission == nil {
		return fmt.Errorf("hostProfile.statelessAdmission is required")
	}
	if p.StatelessAdmission.Capability != StatelessCapability {
		return fmt.Errorf("hostProfile.statelessAdmission.capability is unsupported")
	}
	if !isLowerHexLen(p.StatelessAdmission.Incarnation, 32) {
		return fmt.Errorf("hostProfile.statelessAdmission.incarnation is malformed")
	}
	for _, fam := range p.StatelessAdmission.AssistedFamilies {
		if fam != 4 && fam != 6 {
			return fmt.Errorf("hostProfile.statelessAdmission.assistedFamilies is malformed")
		}
	}
	return nil
}

// MintAdmissionForRegistration mints a client admission token using the
// registration's active admission key and published incarnation.
func (s *Service) MintAdmissionForRegistration(ctx context.Context, registrationID string, claims AdmissionClaims, binding [16]byte, clientUfrag string) (*MintedAdmission, error) {
	reg, err := s.store.GetRegistration(ctx, registrationID)
	if err != nil {
		return nil, errUnknownRegistration()
	}
	epoch, ok := reg.AdmissionKeys[reg.ActiveAdmissionKeyID]
	if !ok || !epoch.Acked {
		return nil, NewError(http.StatusConflict, "admission_key_unacknowledged", "No acknowledged admission key is installed.")
	}
	if reg.Incarnation == "" {
		return nil, NewError(http.StatusConflict, "profile_missing", "The host has not published a stateless admission profile.")
	}
	key := AdmissionKey{KeyID: epoch.KeyID, Secret: epoch.Secret}
	return MintAdmission(key, AdmissionAudience(reg.Incarnation), clientUfrag, claims, binding, s.now())
}

// ResolveHost maps an HTTP Host header to the registration configured for it.
// The header may carry a port the mapping omits.
func (s *Service) ResolveHost(ctx context.Context, host string) (*Registration, error) {
	key := normalizeHost(host)
	if key == "" {
		return nil, ErrNotFound
	}
	s.hostsMu.RLock()
	id, ok := s.hosts[key]
	if !ok {
		if name, _, err := net.SplitHostPort(key); err == nil {
			id, ok = s.hosts[name]
		}
	}
	s.hostsMu.RUnlock()
	if !ok || id == "" {
		return nil, ErrNotFound
	}
	return s.store.GetRegistration(ctx, id)
}

// MapHost adds or replaces a Host-header route at runtime.
func (s *Service) MapHost(host, registrationID string) {
	key := normalizeHost(host)
	if key == "" || registrationID == "" {
		return
	}
	s.hostsMu.Lock()
	defer s.hostsMu.Unlock()
	s.hosts[key] = registrationID
}

// AuthenticateSigned verifies a signed request without requiring a fresh
// sequence. The control WebSocket uses it for its empty-body upgrade.
func (s *Service) AuthenticateSigned(ctx context.Context, req *SignedRequest) (*Registration, error) {
	return s.authenticate(ctx, req)
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Service) bearerReference(token string) (string, bool) {
	digest := tokenDigest(token)
	s.tokensMu.RLock()
	defer s.tokensMu.RUnlock()
	ref, ok := s.bearer[digest]
	return ref, ok
}

func (s *Service) activeBearerCount() int {
	s.tokensMu.RLock()
	defer s.tokensMu.RUnlock()
	return len(s.bearer)
}

// IssueBearerToken mints an attach-instance credential. The token is returned
// exactly once; only its digest is kept.
func (s *Service) IssueBearerToken(label string) (*IssuedBearerToken, error) {
	if err := validateDisplayText(label, 128); err != nil {
		return nil, errInvalidRequest("label " + err.Error())
	}
	token := randomURLToken(32)
	digest := tokenDigest(token)
	ref := "auth_" + digest[:16]
	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()
	if _, exists := s.tokens[ref]; exists {
		return nil, fmt.Errorf("nxs: authorization reference collision")
	}
	now := s.now()
	s.bearer[digest] = ref
	s.tokens[ref] = &bearerRecord{Reference: ref, TokenHash: digest, Label: label, CreatedAt: now}
	return &IssuedBearerToken{
		Token: token, Reference: ref, Label: label, CreatedAt: now.UnixMilli(),
	}, nil
}

// RevokeBearerToken disables an authorization. Revoking twice is harmless.
func (s *Service) RevokeBearerToken(reference string) error {
	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()
	rec, ok := s.tokens[reference]
	if !ok {
		return ErrNotFound
	}
	if rec.RevokedAt == nil {
		now := s.now()
		rec.RevokedAt = &now
		delete(s.bearer, rec.TokenHash)
	}
	return nil
}

// ListBearerTokens returns every authorization without its credential.
func (s *Service) ListBearerTokens() []BearerTokenView {
	s.tokensMu.RLock()
	defer s.tokensMu.RUnlock()
	out := make([]BearerTokenView, 0, len(s.tokens))
	for _, rec := range s.tokens {
		view := BearerTokenView{
			Reference: rec.Reference,
			Label:     rec.Label,
			CreatedAt: rec.CreatedAt.UnixMilli(),
			Active:    rec.RevokedAt == nil,
		}
		if rec.RevokedAt != nil {
			view.RevokedAt = rec.RevokedAt.UnixMilli()
		}
		out = append(out, view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// ListRegistrations returns the administrative projection of every
// registration, including its current readiness.
func (s *Service) ListRegistrations(ctx context.Context) ([]RegistrationView, error) {
	regs, err := s.store.ListRegistrations(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]RegistrationView, 0, len(regs))
	for _, reg := range regs {
		views = append(views, s.viewOf(reg))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].CreatedAt < views[j].CreatedAt })
	return views, nil
}

// GetRegistrationView resolves one administrative registration view by ID.
func (s *Service) GetRegistrationView(ctx context.Context, id string) (*RegistrationView, error) {
	reg, err := s.store.GetRegistration(ctx, id)
	if err != nil {
		return nil, err
	}
	view := s.viewOf(reg)
	return &view, nil
}

func (s *Service) viewOf(reg *Registration) RegistrationView {
	_, expired := s.leaseExpiredAt(reg)
	view := RegistrationView{
		RegistrationID:   reg.RegistrationID,
		InstanceID:       reg.InstanceID,
		ServiceID:        reg.ServiceID,
		Label:            reg.Label,
		LeaseGeneration:  reg.LeaseGeneration,
		ActiveKeyID:      reg.ActiveKeyID,
		AcceptingPlayers: reg.AcceptingPlayers,
		Capacity:         reg.Capacity,
		ConnectedPlayers: reg.ConnectedPlayers,
		CreatedAt:        reg.CreatedAt.UnixMilli(),
		LeaseExpired:     expired,
		Readiness:        s.readiness(reg),
	}
	if !reg.LastHeartbeatAt.IsZero() {
		view.LastHeartbeatAt = reg.LastHeartbeatAt.UnixMilli()
	}
	return view
}

// ReapExpired deletes registrations whose lease has been expired for longer
// than RegistrationRetention. Until then they remain recoverable but are never
// routable while expired.
func (s *Service) ReapExpired(ctx context.Context) (int, error) {
	regs, err := s.store.ListRegistrations(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now()
	deleted := 0
	for _, reg := range regs {
		deadline, expired := s.leaseExpiredAt(reg)
		if !expired || now.Sub(deadline) < s.opts.RegistrationRetention {
			continue
		}
		if err := s.store.DeleteRegistration(ctx, reg.RegistrationID); err != nil {
			if err == ErrNotFound {
				continue
			}
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

// Clone returns a deep copy suitable for transactional updates.
func (r *Registration) Clone() *Registration {
	cp := *r
	cp.Keys = append([]MachineKey(nil), r.Keys...)
	cp.Records = make(map[string]RecordedResponse, len(r.Records))
	for k, v := range r.Records {
		cp.Records[k] = RecordedResponse{BodySHA256: v.BodySHA256, Response: append(json.RawMessage(nil), v.Response...)}
	}
	cp.RecordOrder = append([]string(nil), r.RecordOrder...)
	cp.AdmissionKeys = make(map[string]*AdmissionEpoch, len(r.AdmissionKeys))
	for k, v := range r.AdmissionKeys {
		e := *v
		cp.AdmissionKeys[k] = &e
	}
	cp.AdmissionRequests = make(map[string]string, len(r.AdmissionRequests))
	for k, v := range r.AdmissionRequests {
		cp.AdmissionRequests[k] = v
	}
	cp.ProfileJSON = append([]byte(nil), r.ProfileJSON...)
	if r.ServerStatus != nil {
		s := *r.ServerStatus
		cp.ServerStatus = &s
	}
	if r.Software != nil {
		s := *r.Software
		cp.Software = &s
	}
	cp.BedrockProtocols = append(json.RawMessage(nil), r.BedrockProtocols...)
	cp.Outcomes = append([]OutcomeRecord(nil), r.Outcomes...)
	return &cp
}

func parseJWK(k PublicJWK) (*ecdsa.PublicKey, error) {
	raw, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	_, pub, err := ParsePublicJWK(raw)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func newID(prefix string) string {
	return prefix + "_" + randomHex(16)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("nxs: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func randomURLToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("nxs: crypto/rand failed: " + err.Error())
	}
	return Base64URL(b)
}

func newAdmissionKeyID(existing map[string]*AdmissionEpoch) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for attempt := 0; attempt < 64; attempt++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		out := make([]byte, 4)
		for i := range out {
			out[i] = alphabet[int(b[i])%len(alphabet)]
		}
		id := string(out)
		if _, ok := existing[id]; !ok {
			return id, nil
		}
	}
	return "", fmt.Errorf("nxs: could not allocate an admission key id")
}

func validID(s string) bool {
	return validURLToken(s, 1, 128)
}

func validAdmissionKeyID(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// validURLToken accepts 16..128 (or custom bounds) URL-safe characters.
func validURLToken(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func validateDisplayText(s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("is longer than %d characters", max)
	}
	for _, r := range s {
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
			return fmt.Errorf("contains control characters")
		}
	}
	return nil
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func isLowerHexLen(s string, n int) bool {
	return len(s) == n && isLowerHex(s)
}

// sortedAdmissionKeyIDs is used by tests and diagnostics.
func sortedAdmissionKeyIDs(m map[string]*AdmissionEpoch) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
