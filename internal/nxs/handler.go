package nxs

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Handler exposes the Provider over HTTP. It knows nothing about storage; it
// only decodes NXS v1 wire shapes, extracts signature headers and maps
// protocol errors.
type Handler struct {
	provider Provider
}

// NewHandler builds the HTTP adapter for a provider.
func NewHandler(p Provider) *Handler {
	return &Handler{provider: p}
}

// Mount registers every NXS v1 route on the router.
func (h *Handler) Mount(r chi.Router) {
	r.Get(DiscoveryPath, h.discovery)
	r.Post(OperationPrefix+OpRegister, h.register)
	r.Post(OperationPrefix+OpComplete, h.complete)
	r.Post(OperationPrefix+OpHeartbeat, h.heartbeat)
	r.Post(OperationPrefix+OpOutcomes, h.outcomes)
	r.Post(OperationPrefix+OpRotate, h.rotate)
	r.Post(OperationPrefix+OpRetire, h.retire)
	r.Post(OperationPrefix+OpDeregister, h.deregister)
	r.Post(OperationPrefix+OpOperatorAction, h.operatorAction)
}

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.provider.Discovery())
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if token, ok, err := bearerToken(r); err != nil {
		writeError(w, err)
		return
	} else if ok {
		req.BearerToken = token
	}
	ch, err := h.provider.Register(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, ch)
}

func (h *Handler) complete(w http.ResponseWriter, r *http.Request) {
	var req CompletionRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	reg, err := h.provider.Complete(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, reg)
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	signed, body, err := decodeSigned[HeartbeatRequest](w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := h.provider.Heartbeat(r.Context(), signed, body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, out)
}

func (h *Handler) outcomes(w http.ResponseWriter, r *http.Request) {
	signed, body, err := decodeSigned[OutcomesRequest](w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := h.provider.Outcomes(r.Context(), signed, body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, out)
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	signed, body, err := decodeSigned[RotationRequest](w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := h.provider.Rotate(r.Context(), signed, body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, out)
}

func (h *Handler) retire(w http.ResponseWriter, r *http.Request) {
	signed, body, err := decodeSigned[RetireRequest](w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := h.provider.Retire(r.Context(), signed, body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, out)
}

func (h *Handler) deregister(w http.ResponseWriter, r *http.Request) {
	signed, _, err := decodeSigned[struct{}](w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := h.provider.Deregister(r.Context(), signed)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, out)
}

func (h *Handler) operatorAction(w http.ResponseWriter, r *http.Request) {
	signed, _, err := decodeSigned[struct{}](w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	out, err := h.provider.OperatorAction(r.Context(), signed)
	if err != nil {
		writeError(w, err)
		return
	}
	writeRaw(w, out)
}

func decodeSigned[T any](w http.ResponseWriter, r *http.Request) (*SignedRequest, *T, error) {
	body, err := readBody(w, r)
	if err != nil {
		return nil, nil, err
	}
	version := r.Header.Get("nxs-signature-version")
	if version != SignatureVersion {
		return nil, nil, NewError(http.StatusBadRequest, "unsupported_signature_version", "nxs-signature-version must be "+SignatureVersion+".")
	}
	parse := func(name string) (int64, error) {
		raw := r.Header.Get(name)
		if raw == "" {
			return 0, NewError(http.StatusBadRequest, "invalid_signature_header", "Missing "+name+" header.")
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return 0, NewError(http.StatusBadRequest, "invalid_signature_header", "Malformed "+name+" header.")
		}
		return n, nil
	}
	timestamp, err := parse("nxs-timestamp")
	if err != nil {
		return nil, nil, err
	}
	generation, err := parse("nxs-generation")
	if err != nil {
		return nil, nil, err
	}
	sequence, err := parse("nxs-sequence")
	if err != nil {
		return nil, nil, err
	}

	signed := &SignedRequest{
		Method:         r.Method,
		Path:           r.URL.RequestURI(),
		Body:           body,
		InstanceID:     r.Header.Get("nxs-instance-id"),
		KeyID:          r.Header.Get("nxs-key-id"),
		Signature:      r.Header.Get("nxs-signature"),
		Timestamp:      timestamp,
		Generation:     generation,
		Sequence:       sequence,
		IdempotencyKey: r.Header.Get("idempotency-key"),
	}
	if signed.InstanceID == "" || signed.KeyID == "" || signed.Signature == "" {
		return nil, nil, NewError(http.StatusBadRequest, "invalid_signature_header", "Missing NXS signature headers.")
	}
	var bodyOut T
	if len(body) == 0 {
		return nil, nil, NewError(http.StatusBadRequest, "invalid_request", "A JSON body is required.")
	}
	if err := json.Unmarshal(body, &bodyOut); err != nil {
		return nil, nil, NewError(http.StatusBadRequest, "invalid_request", "The request body is not valid JSON.")
	}
	return signed, &bodyOut, nil
}

func decodeBody(w http.ResponseWriter, r *http.Request, out any) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return NewError(http.StatusBadRequest, "invalid_request", "A JSON body is required.")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return NewError(http.StatusBadRequest, "invalid_request", "The request body is not valid JSON.")
	}
	return nil
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, NewError(http.StatusRequestEntityTooLarge, "body_too_large", "The request body exceeds the provider limit.")
		}
		return nil, NewError(http.StatusBadRequest, "invalid_request", "The request body could not be read.")
	}
	if len(body) > MaxBodyBytes {
		return nil, NewError(http.StatusRequestEntityTooLarge, "body_too_large", "The request body exceeds the provider limit.")
	}
	return body, nil
}

func bearerToken(r *http.Request) (string, bool, error) {
	raw := r.Header.Get("Authorization")
	if raw == "" {
		return "", false, nil
	}
	const prefix = "Bearer "
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return "", false, NewError(http.StatusUnauthorized, "invalid_authorization", "Authorization must use the Bearer scheme.")
	}
	return raw[len(prefix):], true, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
	ActionURL string `json:"actionUrl,omitempty"`
}

func writeError(w http.ResponseWriter, err error) {
	e := AsError(err)
	status := e.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Code: e.Code, Message: e.Message, ActionURL: e.ActionURL})
}
