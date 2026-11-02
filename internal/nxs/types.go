package nxs

import "encoding/json"

// Discovery document (GET DiscoveryPath).
type DiscoveryDocument struct {
	Provider      string                 `json:"provider"`
	Protocols     []string               `json:"protocols"`
	Signatures    []string               `json:"signatures"`
	Authorization DiscoveryAuthorization `json:"authorization"`
	Limits        DiscoveryLimits        `json:"limits"`
	Extensions    map[string]any         `json:"extensions,omitempty"`
}

type DiscoveryAuthorization struct {
	Schemes []string `json:"schemes"`
}

type DiscoveryLimits struct {
	HeartbeatIntervalMs int `json:"heartbeatIntervalMs"`
}

// RegisterRequest accepts both forms: a public key (enrollment) or a
// registrationId (recovery).
type RegisterRequest struct {
	Protocol       string          `json:"protocol"`
	PublicKeyJWK   json.RawMessage `json:"publicKeyJwk"`
	Label          *string         `json:"label"`
	RegistrationID string          `json:"registrationId"`

	// BearerToken is taken from the Authorization header, never from JSON.
	BearerToken string `json:"-"`
}

type ChallengeAuthorization struct {
	Scheme    string `json:"scheme"`
	Reference string `json:"reference"`
}

type ProofOfWork struct {
	Difficulty int `json:"difficulty"`
}

// Challenge is both the wire response and the stored enrollment challenge.
type Challenge struct {
	Protocol      string                  `json:"protocol"`
	Signature     string                  `json:"signature"`
	ChallengeID   string                  `json:"challengeId"`
	Nonce         string                  `json:"nonce"`
	Audience      string                  `json:"audience"`
	Thumbprint    string                  `json:"thumbprint"`
	Context       ChallengeContext        `json:"context"`
	ContextDigest string                  `json:"contextDigest"`
	ExpiresAt     int64                   `json:"expiresAt"`
	ServerTime    int64                   `json:"serverTime"`
	PoW           ProofOfWork             `json:"pow"`
	Authorization *ChallengeAuthorization `json:"authorization,omitempty"`

	// Public key proven by this challenge. For recovery this is the
	// registration's current key, not a key supplied in the request.
	PublicKeyJWK PublicJWK `json:"-"`
	Used         bool      `json:"-"`
	CompletedID  string    `json:"-"`
}

// CompletionRequest is the host's answer to a challenge.
type CompletionRequest struct {
	Protocol       string `json:"protocol"`
	ChallengeID    string `json:"challengeId"`
	ProofNonce     string `json:"proofNonce"`
	Signature      string `json:"signature"`
	IdempotencyKey string `json:"idempotencyKey"`
}

type AdmissionKey struct {
	KeyID  string `json:"keyId"`
	Secret string `json:"secret"`
}

// RegistrationResponse is returned by complete.
type RegistrationResponse struct {
	Protocol        string         `json:"protocol"`
	Provider        string         `json:"provider"`
	RegistrationID  string         `json:"registrationId"`
	InstanceID      string         `json:"instanceId"`
	KeyID           string         `json:"keyId"`
	LeaseGeneration int64          `json:"leaseGeneration"`
	AdmissionKey    *AdmissionKey  `json:"admissionKey,omitempty"`
	Extensions      map[string]any `json:"extensions,omitempty"`
}

// SignedRequest carries the NXS request signature headers and raw body.
type SignedRequest struct {
	Method         string
	Path           string
	Body           []byte
	InstanceID     string
	KeyID          string
	Signature      string
	Timestamp      int64
	Generation     int64
	Sequence       int64
	IdempotencyKey string
}

type ConnectedPlayers struct {
	Count     int64 `json:"count"`
	SampledAt int64 `json:"sampledAt"`
}

type Software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServerStatus struct {
	Name           string `json:"name"`
	Level          string `json:"level"`
	MaxPlayerCount int64  `json:"maxPlayerCount"`
	GameType       int    `json:"gameType"`
}

type StatelessAdmission struct {
	Capability       string `json:"capability"`
	Incarnation      string `json:"incarnation"`
	AssistedFamilies []int  `json:"assistedFamilies,omitempty"`
}

type HostProfile struct {
	Candidates         []json.RawMessage   `json:"candidates"`
	DTLSFingerprint    string              `json:"dtlsFingerprint"`
	AdmissionKeyID     string              `json:"admissionKeyId"`
	SctpPort           int                 `json:"sctpPort"`
	MaxMessageSize     int                 `json:"maxMessageSize"`
	StatelessAdmission *StatelessAdmission `json:"statelessAdmission"`
}

// HeartbeatRequest uses pointers for required members so presence is checked.
type HeartbeatRequest struct {
	AcceptingPlayers         *bool             `json:"acceptingPlayers"`
	Capacity                 *int64            `json:"capacity"`
	ConnectedPlayers         *ConnectedPlayers `json:"connectedPlayers"`
	Software                 *Software         `json:"software"`
	Location                 json.RawMessage   `json:"location"`
	BedrockProtocols         json.RawMessage   `json:"bedrockProtocols"`
	ServerStatus             *ServerStatus     `json:"serverStatus"`
	GameOutcomes             *string           `json:"gameOutcomes"`
	HostProfile              *HostProfile      `json:"hostProfile"`
	HostProfileRevision      *string           `json:"hostProfileRevision"`
	InstalledAdmissionKeyIDs []string          `json:"installedAdmissionKeyIds"`
	AdmissionKeyRequestID    *string           `json:"admissionKeyRequestId"`
	Extensions               json.RawMessage   `json:"extensions"`
}

type Readiness struct {
	Routable bool     `json:"routable"`
	Reasons  []string `json:"reasons"`
}

type CheckIn struct {
	AfterMillis             int64 `json:"afterMillis"`
	LeaseMillis             int64 `json:"leaseMillis"`
	MinUpdateIntervalMillis int64 `json:"minUpdateIntervalMillis"`
}

type AdmissionKeyRequest struct {
	ID    string `json:"id"`
	KeyID string `json:"keyId"`
}

type AdmissionKeyRetirement struct {
	KeyID       string `json:"keyId"`
	RetireAfter int64  `json:"retireAfter"`
}

type HeartbeatResponse struct {
	HostProfileRevision     *string                  `json:"hostProfileRevision"`
	Readiness               Readiness                `json:"readiness"`
	CheckIn                 CheckIn                  `json:"checkIn"`
	AdmissionKeyRequest     *AdmissionKeyRequest     `json:"admissionKeyRequest,omitempty"`
	AdmissionKey            *AdmissionKey            `json:"admissionKey,omitempty"`
	AdmissionKeyRetirements []AdmissionKeyRetirement `json:"admissionKeyRetirements"`
	OperatorActionAvailable *bool                    `json:"operatorActionAvailable,omitempty"`
	Extensions              map[string]any           `json:"extensions,omitempty"`
}

type OutcomeEvent struct {
	TicketID   string  `json:"ticketId"`
	Stage      string  `json:"stage"`
	OccurredAt int64   `json:"occurredAt"`
	Reason     *string `json:"reason"`
}

type OutcomesRequest struct {
	Events []OutcomeEvent `json:"events"`
}

type RotationRequest struct {
	PublicKeyJWK json.RawMessage `json:"publicKeyJwk"`
	Proof        string          `json:"proof"`
}

type RotationResponse struct {
	KeyID           string `json:"keyId"`
	OldKeyRetiresAt int64  `json:"oldKeyRetiresAt,omitempty"`
}

type RetireRequest struct {
	KeyID string `json:"keyId"`
}

type EmptyResponse struct{}

// IssuedBearerToken is returned once, when an operator mints a token. The
// credential is never stored or listed afterwards.
type IssuedBearerToken struct {
	Token     string `json:"token"`
	Reference string `json:"reference"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"createdAt"`
}

// BearerTokenView describes an authorization without revealing its credential.
type BearerTokenView struct {
	Reference string `json:"reference"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"createdAt"`
	RevokedAt int64  `json:"revokedAt,omitempty"`
	Active    bool   `json:"active"`
}

// RegistrationView is the administrative projection of one registration.
type RegistrationView struct {
	RegistrationID   string           `json:"registrationId"`
	InstanceID       string           `json:"instanceId"`
	ServiceID        string           `json:"serviceId"`
	Label            string           `json:"label"`
	LeaseGeneration  int64            `json:"leaseGeneration"`
	ActiveKeyID      string           `json:"activeKeyId"`
	AcceptingPlayers bool             `json:"acceptingPlayers"`
	Capacity         int64            `json:"capacity"`
	ConnectedPlayers ConnectedPlayers `json:"connectedPlayers"`
	LastHeartbeatAt  int64            `json:"lastHeartbeatAt"`
	CreatedAt        int64            `json:"createdAt"`
	LeaseExpired     bool             `json:"leaseExpired"`
	Readiness        Readiness        `json:"readiness"`
}
