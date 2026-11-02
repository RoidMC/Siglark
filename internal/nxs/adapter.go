package nxs

import (
	"context"
	"encoding/json"
	"time"
)

// Provider is the pluggable backend contract, mirroring KexCore's OIDCProvider:
// the HTTP layer only speaks NXS, while storage, token issuance and fleet
// policy live behind this interface.
type Provider interface {
	// Name identifies the backend implementation (e.g. "embedded").
	Name() string

	// Discovery returns the public discovery document.
	Discovery() *DiscoveryDocument

	// Register issues an enrollment or recovery challenge.
	Register(ctx context.Context, req *RegisterRequest) (*Challenge, error)

	// Complete validates the challenge proof and starts a generation.
	Complete(ctx context.Context, req *CompletionRequest) (*RegistrationResponse, error)

	// Signed operational requests. Each returns the exact JSON body to send,
	// already recorded for idempotent replay.
	Heartbeat(ctx context.Context, req *SignedRequest, body *HeartbeatRequest) (json.RawMessage, error)
	Outcomes(ctx context.Context, req *SignedRequest, body *OutcomesRequest) (json.RawMessage, error)
	Rotate(ctx context.Context, req *SignedRequest, body *RotationRequest) (json.RawMessage, error)
	Retire(ctx context.Context, req *SignedRequest, body *RetireRequest) (json.RawMessage, error)
	Deregister(ctx context.Context, req *SignedRequest) (json.RawMessage, error)
	OperatorAction(ctx context.Context, req *SignedRequest) (json.RawMessage, error)
}

// Options configures the embedded provider.
type Options struct {
	Store        Store
	Origin       string
	BearerTokens []string

	ProofOfWorkDifficulty int
	ChallengeTTL          time.Duration

	HeartbeatIntervalMs int64
	LeaseMillis         int64
	MinUpdateIntervalMs int64
	OldKeyRetireAfter   time.Duration

	// RegistrationRetention is how long an expired registration is kept for
	// recovery before ReapExpired deletes it. Defaults to 24 hours.
	RegistrationRetention time.Duration

	// HostMappings routes a public Host header to a registration. Keys are
	// hostnames or host:port pairs as written by clients; values are
	// registration IDs.
	HostMappings map[string]string

	// IdentityTrust decides how client signaling tokens are trusted. "minecraft"
	// (default) validates against the Minecraft authorization service; "any"
	// only requires an expiry but still proves the cpk binding.
	IdentityTrust string

	// WebSocketControl advertises and serves GET /v1/nxs/control.
	WebSocketControl bool

	// AdmissionTTL is the lifetime of a stateless admission token handed to a
	// client during a join. Defaults to 60 seconds and is capped at the protocol
	// maximum.
	AdmissionTTL time.Duration

	// AssistedJoinTimeout bounds how long a join waits for the host's answer.
	// Defaults to 30 seconds.
	AssistedJoinTimeout time.Duration

	Clock func() time.Time
}
