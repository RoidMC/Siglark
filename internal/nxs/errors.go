package nxs

import (
	"errors"
	"net/http"
)

// Error is an NXS protocol error. Errors are wire-visible only through Code,
// Message and ActionURL; anything else must stay in logs.
type Error struct {
	Code       string
	Status     int
	Message    string
	ActionURL  string
	RetryAfter int // seconds; zero means no Retry-After header
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// NewError builds a protocol error with an HTTP status and machine code.
func NewError(status int, code, message string) *Error {
	return &Error{Code: code, Status: status, Message: message}
}

// AsError converts any error into a protocol error, hiding internals.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return NewError(http.StatusInternalServerError, "internal_error", "The provider could not complete the request.")
}

// Errors with semantics fixed by the specification.
var (
	ErrRecoveryRequired    = NewError(http.StatusConflict, "recovery_required", "This completion was already consumed; recover with a fresh challenge.")
	ErrRecoveryUnavailable = NewError(http.StatusForbidden, "recovery_unavailable", "Nothing to recover for this registration.")
	ErrGenerationFenced    = NewError(http.StatusConflict, "generation_fenced", "A newer generation owns this registration.")
)

func errInvalidRequest(message string) *Error {
	return NewError(http.StatusBadRequest, "invalid_request", message)
}

func errInvalidSignature(message string) *Error {
	return NewError(http.StatusUnauthorized, "invalid_signature", message)
}

func errUnknownRegistration() *Error {
	return NewError(http.StatusForbidden, "registration_gone", "The registration no longer exists.")
}

func errChallengeExpired() *Error {
	return NewError(http.StatusBadRequest, "challenge_expired", "The challenge has expired; request a fresh one.")
}

func errInsufficientPoW() *Error {
	return NewError(http.StatusBadRequest, "insufficient_proof_of_work", "The proof of work does not meet the required difficulty.")
}
