// Package boot wires configuration, storage, the NXS provider and the HTTP
// server, mirroring KexCore's boot package.
package boot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/roidmc/siglark/internal/config"
	"github.com/roidmc/siglark/internal/nxs"
	"github.com/roidmc/siglark/internal/storage/file"
	"github.com/roidmc/siglark/internal/storage/memory"
)

// Run loads configuration and serves until SIGINT/SIGTERM.
func Run() error {
	path := os.Getenv("SIGLARK_CONFIG")
	if path == "" {
		path = "config.yaml"
	}
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	setupLogger(cfg.Log)

	store, storeName, err := openStore(cfg.Storage)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	hosts := make(map[string]string, len(cfg.NXS.Hosts))
	identities := make(map[string]*nxs.HostIdentity, len(cfg.NXS.Hosts))
	for _, mapping := range cfg.NXS.Hosts {
		hosts[mapping.Host] = mapping.RegistrationID
		if mapping.IdentityPem == "" {
			continue
		}
		domain := mapping.IdentityDomain
		if domain == "" {
			// The identity domain is the namespace a client tracks the server
			// identity under (first-use trust, like a SSH host-key record).
			domain = "Siglark-SelfhostNXS"
		}
		identity, err := nxs.LoadHostIdentity(mapping.IdentityPem, domain)
		if err != nil {
			return fmt.Errorf("identity for %s: %w", mapping.RegistrationID, err)
		}
		identities[mapping.RegistrationID] = identity
	}
	controlEnabled := cfg.NXS.WebSocketControl == nil || *cfg.NXS.WebSocketControl
	svc, err := nxs.NewService(nxs.Options{
		Store:                 store,
		Origin:                cfg.NXS.ProviderOrigin,
		BearerTokens:          cfg.NXS.BearerTokens,
		ProofOfWorkDifficulty: cfg.NXS.ProofOfWorkDifficulty,
		ChallengeTTL:          time.Duration(cfg.NXS.ChallengeTTLSeconds) * time.Second,
		HeartbeatIntervalMs:   cfg.NXS.HeartbeatIntervalMs,
		LeaseMillis:           cfg.NXS.LeaseMillis,
		MinUpdateIntervalMs:   cfg.NXS.MinUpdateIntervalMs,
		OldKeyRetireAfter:     time.Duration(cfg.NXS.OldKeyRetireSeconds) * time.Second,
		RegistrationRetention: time.Duration(cfg.NXS.RegistrationRetentionSeconds) * time.Second,
		HostMappings:          hosts,
		IdentityTrust:         cfg.NXS.IdentityTrust,
		WebSocketControl:      controlEnabled,
		AdmissionTTL:          time.Duration(cfg.NXS.AdmissionTTLSeconds) * time.Second,
		AssistedJoinTimeout:   time.Duration(cfg.NXS.AssistedJoinTimeoutMs) * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("provider: %w", err)
	}
	sweepCtx, stopSweep := context.WithCancel(context.Background())
	defer stopSweep()
	go sweepLoop(sweepCtx, svc, time.Duration(cfg.NXS.SweepIntervalSeconds)*time.Second)

	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(middleware.RealIP)
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := store.Health(r.Context()); err != nil {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	nxs.NewHandler(svc).Mount(router)
	hub := nxs.NewControlHub(svc, nxs.ControlOptions{
		AssistedJoinTimeout: time.Duration(cfg.NXS.AssistedJoinTimeoutMs) * time.Millisecond,
	})
	if controlEnabled {
		hub.Mount(router)
	}
	nxs.NewJoinHandler(svc, hub, identities).Mount(router)
	nxs.NewAdminHandler(svc, cfg.NXS.AdminToken).Mount(router)

	srv := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port),
		Handler:        router,
		ReadTimeout:    time.Duration(cfg.HTTP.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(cfg.HTTP.WriteTimeout) * time.Second,
		MaxHeaderBytes: cfg.HTTP.MaxHeaderBytes,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("siglark: server starting", "addr", srv.Addr, "origin", cfg.NXS.ProviderOrigin, "store", storeName)
		if cfg.HTTP.TLS.Enabled {
			errCh <- srv.ListenAndServeTLS(cfg.HTTP.TLS.CertFile, cfg.HTTP.TLS.KeyFile)
			return
		}
		errCh <- srv.ListenAndServe()
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-quit:
	}

	slog.Info("siglark: shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.HTTP.ShutdownTimeout)*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("siglark: forced shutdown", "error", err)
	}
	return nil
}

func openStore(cfg config.StorageConfig) (nxs.Store, string, error) {
	switch strings.ToLower(cfg.Driver) {
	case "memory":
		return memory.New(), "memory", nil
	case "file":
		store, err := file.New(cfg.Path)
		if err != nil {
			return nil, "", err
		}
		return store, "file:" + cfg.Path, nil
	default:
		return nil, "", fmt.Errorf("unknown driver %q", cfg.Driver)
	}
}

func sweepLoop(ctx context.Context, svc *nxs.Service, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count, err := svc.ReapExpired(ctx)
			if err != nil {
				slog.Warn("siglark: lease sweep failed", "error", err)
				continue
			}
			if count > 0 {
				slog.Info("siglark: reclaimed expired registrations", "count", count)
			}
		}
	}
}

func setupLogger(cfg config.LogConfig) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.EqualFold(cfg.Format, "text") {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}
