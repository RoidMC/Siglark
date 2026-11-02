// Package config loads Siglark's YAML configuration.
package config

import (
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	HTTP    HTTPConfig    `yaml:"http"`
	Storage StorageConfig `yaml:"storage"`
	NXS     NXSConfig     `yaml:"nxs"`
	Log     LogConfig     `yaml:"log"`
}

// StorageConfig selects the Store implementation.
type StorageConfig struct {
	// Driver is "file" or "memory".
	Driver string `yaml:"driver"`
	// Path is the durable snapshot used by the file driver.
	Path string `yaml:"path"`
}

type ServerConfig struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Env     string `yaml:"env"`
}

type HTTPConfig struct {
	Host            string    `yaml:"host"`
	Port            int       `yaml:"port"`
	ReadTimeout     int       `yaml:"read_timeout"`
	WriteTimeout    int       `yaml:"write_timeout"`
	ShutdownTimeout int       `yaml:"shutdown_timeout"`
	MaxHeaderBytes  int       `yaml:"max_header_bytes"`
	TLS             TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// NXSConfig is the operator-facing protocol surface.
type NXSConfig struct {
	// ProviderOrigin is the canonical origin every signature audience uses.
	// It must match the origin clients configure exactly.
	ProviderOrigin string `yaml:"provider_origin"`

	// BearerTokens register with attach-instance authority. Tokens are never
	// logged and never appear in challenge bodies.
	BearerTokens []string `yaml:"bearer_tokens"`

	ProofOfWorkDifficulty int `yaml:"proof_of_work_difficulty"`
	ChallengeTTLSeconds   int `yaml:"challenge_ttl_seconds"`

	HeartbeatIntervalMs int64 `yaml:"heartbeat_interval_ms"`
	LeaseMillis         int64 `yaml:"lease_millis"`
	MinUpdateIntervalMs int64 `yaml:"min_update_interval_ms"`

	OldKeyRetireSeconds int `yaml:"old_key_retire_seconds"`

	// AdminToken protects the minimal operator API. Empty disables the API.
	AdminToken string `yaml:"admin_token"`
	// RegistrationRetentionSeconds is how long an expired registration stays
	// recoverable before it is reclaimed.
	RegistrationRetentionSeconds int `yaml:"registration_retention_seconds"`
	// SweepIntervalSeconds is how often expired registrations are reclaimed.
	SweepIntervalSeconds int `yaml:"sweep_interval_seconds"`

	// Hosts routes a public Host header to a registration so one provider can
	// serve several hosts.
	Hosts []HostMapping `yaml:"hosts"`

	// IdentityTrust is "minecraft" (default) or "any".
	IdentityTrust string `yaml:"identity_trust"`
	// AdmissionTTLSeconds is the lifetime of a client admission token.
	AdmissionTTLSeconds int `yaml:"admission_ttl_seconds"`
	// AssistedJoinTimeoutMs bounds the wait for a host's join answer.
	AssistedJoinTimeoutMs int64 `yaml:"assisted_join_timeout_ms"`
	// WebSocketControl enables the optional control carrier. Defaults to on.
	WebSocketControl *bool `yaml:"websocket_control"`
}

// HostMapping ties a public host name to one registration.
type HostMapping struct {
	Host           string `yaml:"host"`
	RegistrationID string `yaml:"registration_id"`
	// IdentityPem optionally points at the host's P-384 identity PEM. When
	// set, the provider signs a server identity assertion into the answer.
	IdentityPem string `yaml:"identity_pem"`
	// IdentityDomain is the issuer recorded in that assertion and the
	// namespace a client tracks the identity under. It defaults to
	// "Siglark-SelfhostNXS".
	IdentityDomain string `yaml:"identity_domain"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	setDefaults(cfg)
	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Server.Name == "" {
		cfg.Server.Name = "siglark"
	}
	if cfg.Server.Version == "" {
		cfg.Server.Version = "0.1.0"
	}
	if cfg.Server.Env == "" {
		cfg.Server.Env = "development"
	}
	if cfg.HTTP.Host == "" {
		cfg.HTTP.Host = "0.0.0.0"
	}
	if cfg.HTTP.Port == 0 {
		cfg.HTTP.Port = 8080
	}
	if cfg.HTTP.ReadTimeout == 0 {
		cfg.HTTP.ReadTimeout = 30
	}
	if cfg.HTTP.WriteTimeout == 0 {
		cfg.HTTP.WriteTimeout = 30
	}
	if cfg.HTTP.ShutdownTimeout == 0 {
		cfg.HTTP.ShutdownTimeout = 10
	}
	if cfg.HTTP.MaxHeaderBytes == 0 {
		cfg.HTTP.MaxHeaderBytes = 1 << 20
	}
	if cfg.Storage.Driver == "" {
		cfg.Storage.Driver = "file"
	}
	if cfg.Storage.Path == "" {
		cfg.Storage.Path = "data/siglark.json"
	}
	if cfg.NXS.ProviderOrigin == "" {
		cfg.NXS.ProviderOrigin = "http://localhost:8080"
	}
	if cfg.NXS.ProofOfWorkDifficulty < 0 {
		cfg.NXS.ProofOfWorkDifficulty = 0
	}
	if cfg.NXS.ProofOfWorkDifficulty > 24 {
		cfg.NXS.ProofOfWorkDifficulty = 24
	}
	if cfg.NXS.ChallengeTTLSeconds == 0 {
		cfg.NXS.ChallengeTTLSeconds = 300
	}
	if cfg.NXS.HeartbeatIntervalMs == 0 {
		cfg.NXS.HeartbeatIntervalMs = 10000
	}
	if cfg.NXS.LeaseMillis == 0 {
		cfg.NXS.LeaseMillis = cfg.NXS.HeartbeatIntervalMs + 60000
	}
	if cfg.NXS.MinUpdateIntervalMs == 0 {
		cfg.NXS.MinUpdateIntervalMs = 1000
	}
	if cfg.NXS.OldKeyRetireSeconds == 0 {
		cfg.NXS.OldKeyRetireSeconds = 86400
	}
	if cfg.NXS.RegistrationRetentionSeconds == 0 {
		cfg.NXS.RegistrationRetentionSeconds = 86400
	}
	if cfg.NXS.SweepIntervalSeconds == 0 {
		cfg.NXS.SweepIntervalSeconds = 30
	}
	if cfg.NXS.IdentityTrust == "" {
		cfg.NXS.IdentityTrust = "minecraft"
	}
	if cfg.NXS.AdmissionTTLSeconds == 0 {
		cfg.NXS.AdmissionTTLSeconds = 60
	}
	if cfg.NXS.AssistedJoinTimeoutMs == 0 {
		cfg.NXS.AssistedJoinTimeoutMs = 30000
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}
	if cfg.Log.Output == "" {
		cfg.Log.Output = "stdout"
	}
}
