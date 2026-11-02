package nxs

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("nxs: not found")
	ErrChallengeUsed = errors.New("nxs: challenge already consumed")
)

// MachineKey is a persisted P-384 host signing key.
type MachineKey struct {
	KeyID      string    `json:"keyId"`
	X          string    `json:"x"`
	Y          string    `json:"y"`
	Thumbprint string    `json:"thumbprint"`
	CreatedAt  time.Time `json:"createdAt"`
	// RetireAt is the deadline a superseded key stops signing unless it is
	// retired sooner.
	RetireAt  *time.Time `json:"retireAt,omitempty"`
	RetiredAt *time.Time `json:"retiredAt,omitempty"`
}

// JWK returns the stored public JWK.
func (k MachineKey) JWK() PublicJWK {
	return PublicJWK{Crv: "P-384", Kty: "EC", X: k.X, Y: k.Y}
}

// AdmissionEpoch is one stateless-admission key epoch.
type AdmissionEpoch struct {
	KeyID     string    `json:"keyId"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"createdAt"`
	Acked     bool      `json:"acked"`
}

// RecordedResponse is the idempotent replay record for a signed request.
type RecordedResponse struct {
	BodySHA256 string          `json:"bodySha256"`
	Response   json.RawMessage `json:"response"`
}

// OutcomeRecord is one reported transport/game observation.
type OutcomeRecord struct {
	TicketID   string `json:"ticketId"`
	Stage      string `json:"stage"`
	OccurredAt int64  `json:"occurredAt"`
	Reason     string `json:"reason,omitempty"`
}

// Registration is the provider's persisted view of one runtime identity.
type Registration struct {
	RegistrationID string `json:"registrationId"`
	InstanceID     string `json:"instanceId"`
	ServiceID      string `json:"serviceId"`
	Label          string `json:"label"`

	LeaseGeneration int64        `json:"leaseGeneration"`
	Keys            []MachineKey `json:"keys"`
	ActiveKeyID     string       `json:"activeKeyId"`
	LastSequence    int64        `json:"lastSequence"`

	Records              map[string]RecordedResponse `json:"records"`
	RecordOrder          []string                    `json:"recordOrder"`
	AdmissionKeys        map[string]*AdmissionEpoch  `json:"admissionKeys"`
	ActiveAdmissionKeyID string                      `json:"activeAdmissionKeyId"`
	AdmissionRequests    map[string]string           `json:"admissionRequests"`

	ProfileRevision string `json:"profileRevision"`
	ProfileJSON     []byte `json:"profileJson"`
	Incarnation     string `json:"incarnation"`

	AcceptingPlayers bool             `json:"acceptingPlayers"`
	Capacity         int64            `json:"capacity"`
	ConnectedPlayers ConnectedPlayers `json:"connectedPlayers"`

	// Listing observations carried by heartbeats. ServerStatus and Software are
	// kept as last reported; BedrockProtocols holds the wire object or null.
	ServerStatus     *ServerStatus   `json:"serverStatus,omitempty"`
	Software         *Software       `json:"software,omitempty"`
	BedrockProtocols json.RawMessage `json:"bedrockProtocols,omitempty"`

	Outcomes        []OutcomeRecord `json:"outcomes"`
	LastHeartbeatAt time.Time       `json:"lastHeartbeatAt"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

// KeyByID returns a non-retired key by ID.
func (r *Registration) KeyByID(keyID string) (MachineKey, bool) {
	for _, k := range r.Keys {
		if k.KeyID == keyID && k.RetiredAt == nil {
			return k, true
		}
	}
	return MachineKey{}, false
}

// ActiveKey returns the current machine key.
func (r *Registration) ActiveKey() (MachineKey, bool) {
	return r.KeyByID(r.ActiveKeyID)
}

// IsCurrentKeyThumbprint reports whether thumbprint belongs to the active,
// non-retired machine key.
func (r *Registration) IsCurrentKeyThumbprint(thumbprint string) bool {
	k, ok := r.ActiveKey()
	return ok && k.Thumbprint == thumbprint
}

// Store is the persistence boundary. Implementations must serialize updates
// per registration; callbacks passed to CompleteChallenge and
// UpdateRegistration run under that lock.
type Store interface {
	Health(ctx context.Context) error

	PutChallenge(ctx context.Context, c *Challenge) error
	GetChallenge(ctx context.Context, id string) (*Challenge, error)
	// CompleteChallenge consumes the challenge and saves the registration
	// returned by fn atomically. existing is the registration named by the
	// challenge's recovery context, or nil. It returns ErrChallengeUsed when
	// the challenge was already consumed.
	CompleteChallenge(ctx context.Context, challengeID string, fn func(*Challenge, *Registration) (*Registration, error)) error

	GetRegistration(ctx context.Context, id string) (*Registration, error)
	// GetRegistrationByInstance resolves the registration that owns the given
	// runtime instance ID. Signed requests identify themselves by instanceId,
	// while the store is keyed by registrationId.
	GetRegistrationByInstance(ctx context.Context, instanceID string) (*Registration, error)
	// ListRegistrations returns every stored registration. The caller owns the
	// returned copies; implementations must not expose their internal maps.
	ListRegistrations(ctx context.Context) ([]*Registration, error)
	UpdateRegistration(ctx context.Context, id string, fn func(*Registration) error) error
	DeleteRegistration(ctx context.Context, id string) error
}
