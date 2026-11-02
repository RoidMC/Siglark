package nxs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

// ControlPath is the optional WebSocket carrier for signed operations and
// assisted joins.
const ControlPath = "/v1/nxs/control"

// Control frame kinds.
const (
	kindOperation          = "operation"
	kindResponse           = "response"
	kindAssistedJoin       = "assisted-join"
	kindAssistedJoinResult = "assisted-join-result"
)

// extensionWebSocket advertises the control carrier in discovery.
const extensionWebSocket = "dev.opencollab.nxs.websocket"

// ControlOptions tunes the WebSocket carrier.
type ControlOptions struct {
	// AssistedJoinTimeout bounds how long a join waits for the host's answer.
	AssistedJoinTimeout time.Duration
}

// ControlHub owns every authenticated control socket, keyed by instance ID.
// Operations are dispatched to the same Service used by the HTTPS carrier.
type ControlHub struct {
	svc      *Service
	timeout  time.Duration
	upgrader websocket.Upgrader

	mu       sync.RWMutex
	sessions map[string]*controlSession
}

// NewControlHub builds the carrier. It does not read Service options for the
// timeout; pass it explicitly or leave zero for 30 seconds.
func NewControlHub(svc *Service, opts ControlOptions) *ControlHub {
	timeout := opts.AssistedJoinTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	return &ControlHub{
		svc:     svc,
		timeout: timeout,
		upgrader: websocket.Upgrader{
			Subprotocols:    []string{Protocol},
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			// Authentication is carried by signed headers, which a browser
			// cannot forge, so Origin grants nothing here.
			CheckOrigin: func(*http.Request) bool { return true },
		},
		sessions: map[string]*controlSession{},
	}
}

// Mount registers the control endpoint.
func (h *ControlHub) Mount(r chi.Router) {
	r.Get(ControlPath, h.handle)
}

func (h *ControlHub) handle(w http.ResponseWriter, r *http.Request) {
	if !h.svc.opts.WebSocketControl {
		writeError(w, NewError(http.StatusNotFound, "not_found", "The WebSocket carrier is disabled."))
		return
	}
	req, err := signedRequestFromHeaders(r, http.MethodGet, ControlPath)
	if err != nil {
		writeError(w, err)
		return
	}
	reg, err := h.svc.AuthenticateSigned(r.Context(), req)
	if err != nil {
		writeError(w, err)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	assisted := r.Header.Get("nxs-assisted") == "1"
	slog.Debug("nxs: control socket opened",
		"instanceId", reg.InstanceID, "generation", req.Generation, "assisted", assisted)
	session := &controlSession{
		hub:        h,
		conn:       conn,
		instanceID: reg.InstanceID,
		generation: req.Generation,
		assisted:   assisted,
		attempts:   map[string]chan assistResult{},
		networks:   map[string]bool{},
	}
	h.addSession(session)
	defer h.removeSession(session)
	session.readLoop(r.Context())
}

func (h *ControlHub) addSession(s *controlSession) {
	h.mu.Lock()
	previous := h.sessions[s.instanceID]
	h.sessions[s.instanceID] = s
	h.mu.Unlock()
	if previous != nil && previous != s {
		previous.failAll()
		_ = previous.conn.Close()
	}
}

func (h *ControlHub) removeSession(s *controlSession) {
	h.mu.Lock()
	if current := h.sessions[s.instanceID]; current == s {
		delete(h.sessions, s.instanceID)
	}
	h.mu.Unlock()
}

func (h *ControlHub) session(instanceID string) *controlSession {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[instanceID]
}

// AssistRequest is the provider's side of one assisted join.
type AssistRequest struct {
	InstanceID      string
	Generation      int64
	Incarnation     string
	KeyID           string
	HostFingerprint string
	NetworkID       string
	CPK             string
	LocalUfrag      string
	LocalPassword   string
	Offer           string
}

type assistResult struct {
	answer string
	status int
	reason string
}

// Err values returned by Assist carry an HTTP status the join handler copies.
var (
	errHostUnavailable = NewError(http.StatusServiceUnavailable, "host_unavailable", "No live host socket can answer this join.")
	errDuplicateJoin   = NewError(http.StatusConflict, "duplicate_join", "Another join for this network ID is already pending.")
	errJoinTimeout     = NewError(http.StatusGatewayTimeout, "join_timeout", "The host did not answer in time.")
	errJoinRejected    = NewError(http.StatusForbidden, "join_rejected", "The host refused the join.")
)

// Assist hands one client offer to the host socket and waits for its answer.
func (h *ControlHub) Assist(ctx context.Context, req AssistRequest) (string, error) {
	if req.InstanceID == "" || req.Offer == "" || len(req.Offer) > maxOfferBodyBytes {
		return "", errInvalidRequest("assisted join request is malformed")
	}
	session := h.session(req.InstanceID)
	if session == nil {
		slog.Debug("nxs: assisted join has no control socket", "instanceId", req.InstanceID)
		return "", errHostUnavailable
	}
	if !session.assisted {
		slog.Debug("nxs: control socket did not opt into assisted joins", "instanceId", req.InstanceID)
		return "", errHostUnavailable
	}
	if session.generation != req.Generation {
		slog.Debug("nxs: assisted join generation mismatch",
			"instanceId", req.InstanceID, "socketGeneration", session.generation, "requestGeneration", req.Generation)
		return "", errHostUnavailable
	}

	attemptID, err := newAttemptID()
	if err != nil {
		return "", err
	}
	answer := make(chan assistResult, 1)
	if !session.reserve(req.NetworkID, attemptID, answer) {
		return "", errDuplicateJoin
	}
	defer session.release(req.NetworkID, attemptID)

	expiresAt := h.svc.now().Add(h.timeout).UnixMilli()
	frame := map[string]any{
		"kind":            kindAssistedJoin,
		"version":         1,
		"id":              attemptID,
		"instanceId":      req.InstanceID,
		"generation":      req.Generation,
		"incarnation":     req.Incarnation,
		"keyId":           req.KeyID,
		"hostFingerprint": req.HostFingerprint,
		"expiresAt":       expiresAt,
		"networkId":       req.NetworkID,
		"localUfrag":      req.LocalUfrag,
		"localPassword":   req.LocalPassword,
		"offer":           req.Offer,
	}
	if req.NetworkID != "0" {
		frame["cpk"] = req.CPK
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		return "", err
	}
	if err := session.writeText(string(raw)); err != nil {
		return "", errHostUnavailable
	}
	slog.Debug("nxs: assisted join sent", "id", attemptID, "keyId", req.KeyID,
		"generation", req.Generation, "incarnation", req.Incarnation,
		"hostFingerprint", req.HostFingerprint, "expiresAt", expiresAt,
		"networkId", req.NetworkID, "cpk", req.CPK, "offer", req.Offer)

	timer := time.NewTimer(h.timeout)
	defer timer.Stop()
	select {
	case result := <-answer:
		if result.status != 0 {
			return "", NewError(result.status, "assisted_join_failed", result.reason)
		}
		return result.answer, nil
	case <-timer.C:
		return "", errJoinTimeout
	case <-ctx.Done():
		return "", errJoinTimeout
	}
}

func newAttemptID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// controlSession is one authenticated socket. Writes are serialized; attempts
// are shared with the join path.
type controlSession struct {
	hub        *ControlHub
	conn       *websocket.Conn
	instanceID string
	generation int64
	assisted   bool

	writeMu  sync.Mutex
	mu       sync.Mutex
	attempts map[string]chan assistResult
	networks map[string]bool
	closed   bool
}

func (s *controlSession) reserve(networkID, attemptID string, ch chan assistResult) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.networks[networkID] {
		return false
	}
	s.networks[networkID] = true
	s.attempts[attemptID] = ch
	return true
}

func (s *controlSession) release(networkID, attemptID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attempts, attemptID)
	delete(s.networks, networkID)
}

func (s *controlSession) attemptsInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.attempts)
}

// failAll unblocks every waiting join with a single refusal.
func (s *controlSession) failAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for id, ch := range s.attempts {
		select {
		case ch <- assistResult{status: http.StatusServiceUnavailable, reason: "host socket closed"}:
		default:
		}
		delete(s.attempts, id)
	}
	s.networks = map[string]bool{}
}

func (s *controlSession) deliver(attemptID string, result assistResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.attempts[attemptID]
	if !ok {
		return
	}
	select {
	case ch <- result:
	default:
	}
	delete(s.attempts, attemptID)
}

func (s *controlSession) writeText(text string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return s.conn.WriteMessage(websocket.TextMessage, []byte(text))
}

func (s *controlSession) readLoop(ctx context.Context) {
	s.conn.SetReadLimit(maxControlMessageBytes)
	defer func() {
		s.failAll()
		_ = s.conn.Close()
	}()
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			return
		}
		text := string(data)
		if text == "ping" {
			if err := s.writeText("pong"); err != nil {
				return
			}
			continue
		}
		if text == "pong" {
			continue
		}
		if err := s.handleFrame(ctx, text); err != nil {
			if errors.Is(err, errCloseFrame) {
				_ = s.writeControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "invalid frame"))
			}
			return
		}
	}
}

func (s *controlSession) writeControl(kind int, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteControl(kind, payload, time.Now().Add(5*time.Second))
}

var errCloseFrame = errors.New("nxs: invalid control frame")

func (s *controlSession) handleFrame(ctx context.Context, text string) error {
	var envelope struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(text), &envelope); err != nil {
		return errCloseFrame
	}
	switch envelope.Kind {
	case kindOperation:
		return s.handleOperation(ctx, text)
	case kindAssistedJoinResult:
		return s.handleAssistedResult(text)
	default:
		// Frames of unknown kinds are for receivers that understand them.
		return nil
	}
}

func (s *controlSession) handleOperation(ctx context.Context, text string) error {
	var frame struct {
		Kind      string            `json:"kind"`
		Operation string            `json:"operation"`
		Headers   map[string]string `json:"headers"`
		Body      string            `json:"body"`
	}
	if err := json.Unmarshal([]byte(text), &frame); err != nil {
		return errCloseFrame
	}
	if !isControlOperation(frame.Operation) || frame.Headers == nil {
		return errCloseFrame
	}
	if len(frame.Body) > MaxBodyBytes {
		return errCloseFrame
	}
	headers := make(map[string]string, len(frame.Headers))
	for name, value := range frame.Headers {
		headers[strings.ToLower(name)] = value
	}
	req, err := signedRequestFromValues(http.MethodPost, OperationPrefix+frame.Operation, []byte(frame.Body), headers)
	if err != nil {
		return errCloseFrame
	}

	status := http.StatusOK
	var out json.RawMessage
	switch frame.Operation {
	case OpHeartbeat:
		var body HeartbeatRequest
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return errCloseFrame
		}
		out, err = s.hub.svc.Heartbeat(ctx, req, &body)
	case OpOutcomes:
		var body OutcomesRequest
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return errCloseFrame
		}
		out, err = s.hub.svc.Outcomes(ctx, req, &body)
	case OpRotate:
		var body RotationRequest
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return errCloseFrame
		}
		out, err = s.hub.svc.Rotate(ctx, req, &body)
	case OpRetire:
		var body RetireRequest
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return errCloseFrame
		}
		out, err = s.hub.svc.Retire(ctx, req, &body)
	case OpDeregister:
		out, err = s.hub.svc.Deregister(ctx, req)
	}
	if err != nil {
		proto := AsError(err)
		status = proto.Status
		if status == 0 {
			status = http.StatusInternalServerError
		}
		encoded, _ := json.Marshal(errorBody{Code: proto.Code, Message: proto.Message, ActionURL: proto.ActionURL})
		out = encoded
	}
	responseHeaders := map[string]string{"content-type": "application/json"}
	if err != nil {
		if proto := AsError(err); proto.RetryAfter > 0 {
			responseHeaders["retry-after"] = strconv.Itoa(proto.RetryAfter)
		}
	}
	return s.writeResponse(req.IdempotencyKey, status, responseHeaders, string(out))
}

func (s *controlSession) writeResponse(id string, status int, headers map[string]string, body string) error {
	frame := map[string]any{
		"kind":    kindResponse,
		"id":      id,
		"status":  status,
		"headers": headers,
		"body":    body,
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return s.writeText(string(raw))
}

func (s *controlSession) handleAssistedResult(text string) error {
	var frame struct {
		Kind     string `json:"kind"`
		ID       string `json:"id"`
		Accepted *bool  `json:"accepted"`
		Answer   string `json:"answer"`
	}
	if err := json.Unmarshal([]byte(text), &frame); err != nil {
		return errCloseFrame
	}
	if len(frame.ID) != 32 || !isLowerHex(frame.ID) || frame.Accepted == nil {
		return errCloseFrame
	}
	if *frame.Accepted {
		if frame.Answer == "" || len(frame.Answer) > maxAnswerBodyBytes {
			return errCloseFrame
		}
		s.deliver(frame.ID, assistResult{answer: frame.Answer})
		return nil
	}
	slog.Debug("nxs: host refused assisted join", "raw", text[:min(len(text), 512)])
	s.deliver(frame.ID, assistResult{status: http.StatusForbidden, reason: "the host refused the join"})
	return nil
}

func isControlOperation(op string) bool {
	switch op {
	case OpHeartbeat, OpOutcomes, OpRotate, OpRetire, OpDeregister:
		return true
	default:
		return false
	}
}

// signedRequestFromHeaders reads the NXS signature headers for a request
// without a JSON body, as the control upgrade requires.
func signedRequestFromHeaders(r *http.Request, method, path string) (*SignedRequest, error) {
	headers := map[string]string{}
	for _, name := range []string{
		"nxs-instance-id", "nxs-key-id", "nxs-timestamp", "nxs-signature-version",
		"nxs-generation", "nxs-sequence", "idempotency-key", "nxs-signature",
	} {
		headers[name] = r.Header.Get(name)
	}
	return signedRequestFromValues(method, path, []byte{}, headers)
}

func signedRequestFromValues(method, path string, body []byte, headers map[string]string) (*SignedRequest, error) {
	if headers["nxs-signature-version"] != SignatureVersion {
		return nil, NewError(http.StatusBadRequest, "unsupported_signature_version", "nxs-signature-version must be "+SignatureVersion+".")
	}
	parse := func(name string) (int64, error) {
		raw := headers[name]
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
		return nil, err
	}
	generation, err := parse("nxs-generation")
	if err != nil {
		return nil, err
	}
	sequence, err := parse("nxs-sequence")
	if err != nil {
		return nil, err
	}
	req := &SignedRequest{
		Method:         method,
		Path:           path,
		Body:           body,
		InstanceID:     headers["nxs-instance-id"],
		KeyID:          headers["nxs-key-id"],
		Signature:      headers["nxs-signature"],
		Timestamp:      timestamp,
		Generation:     generation,
		Sequence:       sequence,
		IdempotencyKey: headers["idempotency-key"],
	}
	if req.InstanceID == "" || req.KeyID == "" || req.Signature == "" {
		return nil, NewError(http.StatusBadRequest, "invalid_signature_header", "Missing NXS signature headers.")
	}
	if req.IdempotencyKey == "" {
		return nil, NewError(http.StatusBadRequest, "invalid_signature_header", "Missing idempotency-key header.")
	}
	if !validURLToken(req.IdempotencyKey, 16, 128) {
		return nil, NewError(http.StatusBadRequest, "invalid_request", "idempotency-key header is malformed.")
	}
	return req, nil
}
