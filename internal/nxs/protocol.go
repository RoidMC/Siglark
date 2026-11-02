// Package nxs implements the provider side of NetherNet External Signaling v1.
//
// The package is deliberately split the same way as KexCore's OIDC OP:
//
//	HTTP (handler.go) ──► Provider (adapter.go) ──► Service (service.go) ──► Store
//
// Any backend that implements Store can host the protocol; the wire format and
// signature rules stay in the core package.
package nxs

const (
	// Protocol is the NXS v1 registration/request protocol identifier.
	Protocol = "nethernet-external-signaling-v1"

	// SignatureVersion is the ES384 machine request signature identifier.
	SignatureVersion = "nxs-es384-v1"

	// DiscoveryPath is the unauthenticated discovery document.
	DiscoveryPath = "/.well-known/nethernet-external-signaling"

	// OperationPrefix is the path prefix for every operation.
	OperationPrefix = "/v1/nxs/"

	// AdmissionPrefix prefixes the stateless admission carrier.
	AdmissionPrefix = "NXS1"

	// StatelessCapability is the discovery capability name for stateless admission.
	StatelessCapability = "nethernet.stateless-admission.v1"

	// MaxBodyBytes is the largest request body a provider accepts.
	MaxBodyBytes = 65536

	// MaxClockSkewSeconds is the accepted request timestamp skew.
	MaxClockSkewSeconds = 60

	// MaxAdmissionTTLSkewSeconds is the largest allowed forward token distance.
	MaxAdmissionTTLSkewSeconds = 120
)

// Operation names. Every operation is a POST under OperationPrefix.
const (
	OpRegister       = "register"
	OpComplete       = "complete"
	OpHeartbeat      = "heartbeat"
	OpOutcomes       = "outcomes"
	OpRotate         = "rotate"
	OpRetire         = "retire"
	OpDeregister     = "deregister"
	OpOperatorAction = "operator-action"
)
