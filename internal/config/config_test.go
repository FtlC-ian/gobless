package config

import (
	"bytes"
	"encoding/base64"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		env     map[string]string
		want    func(*testing.T, *Config)
		wantErr string
		wantLog string
	}{
		{
			name: "valid config from file",
			path: filepath.Join("..", "..", "testdata", "config", "valid_rsa.cfg"),
			want: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.CA.PrivateKeyFile != "/tmp/gobless-test-ca" {
					t.Fatalf("PrivateKeyFile = %q", cfg.CA.PrivateKeyFile)
				}
				if cfg.CA.SignerType != "rsa" || cfg.CA.DefaultTTL != 300 || cfg.CA.MaxTTL != 600 || cfg.CA.RSAMinKeyBits != 2048 {
					t.Fatalf("unexpected CA config: %+v", cfg.CA)
				}
				if len(cfg.Principal.Allowed) != 2 || cfg.Principal.Allowed[0] != "alice" || cfg.Principal.Allowed[1] != "bob" {
					t.Fatalf("Allowed = %#v", cfg.Principal.Allowed)
				}
			},
		},
		{
			name: "valid config from env only",
			env: map[string]string{
				"GOBLESS_CA_KMS_KEY_ID":         "alias/gobless-test",
				"GOBLESS_CA_SIGNER_TYPE":        "kms",
				"GOBLESS_CA_DEFAULT_TTL":        "120",
				"GOBLESS_CA_MAX_TTL":            "300",
				"GOBLESS_LAMBDA_REGION":         "us-east-1",
				"GOBLESS_LOGGING_AUDIT_ENABLED": "true",
			},
			want: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.CA.KMSKeyID != "alias/gobless-test" || cfg.CA.SignerType != "kms" {
					t.Fatalf("unexpected KMS config: %+v", cfg.CA)
				}
				if cfg.CA.RSAMinKeyBits != 2048 {
					t.Fatalf("RSAMinKeyBits default = %d", cfg.CA.RSAMinKeyBits)
				}
				if !cfg.Logging.AuditEnabled {
					t.Fatal("AuditEnabled = false")
				}
			},
		},
		{
			name: "env overrides file value",
			path: filepath.Join("..", "..", "testdata", "config", "valid_rsa.cfg"),
			env: map[string]string{
				"GOBLESS_CA_DEFAULT_TTL": "450",
				"GOBLESS_LOGGING_LEVEL":  "debug",
			},
			want: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.CA.DefaultTTL != 450 {
					t.Fatalf("DefaultTTL = %d", cfg.CA.DefaultTTL)
				}
				if cfg.Logging.Level != "debug" {
					t.Fatalf("Logging.Level = %q", cfg.Logging.Level)
				}
			},
		},
		{
			name:    "missing required fields",
			path:    filepath.Join("..", "..", "testdata", "config", "missing_key.cfg"),
			wantErr: "at least one",
		},
		{
			name: "RSA min key bits too small",
			env: map[string]string{
				"GOBLESS_CA_PRIVATE_KEY_FILE": "/tmp/key",
				"GOBLESS_CA_SIGNER_TYPE":      "rsa",
				"GOBLESS_CA_DEFAULT_TTL":      "300",
				"GOBLESS_CA_MAX_TTL":          "600",
				"GOBLESS_CA_RSA_MIN_KEY_BITS": "1024",
			},
			wantErr: "RSAMinKeyBits",
		},
		{
			name: "max TTL less than default TTL",
			env: map[string]string{
				"GOBLESS_CA_PRIVATE_KEY_FILE": "/tmp/key",
				"GOBLESS_CA_SIGNER_TYPE":      "rsa",
				"GOBLESS_CA_DEFAULT_TTL":      "601",
				"GOBLESS_CA_MAX_TTL":          "600",
			},
			wantErr: "DefaultTTL must be <= CA.MaxTTL",
		},
		{
			name:    "audit fail open logs warning and succeeds",
			path:    filepath.Join("..", "..", "testdata", "config", "audit_failopen.cfg"),
			wantLog: "WARNING: audit fail-open is enabled",
			want: func(t *testing.T, cfg *Config) {
				t.Helper()
				if !cfg.Logging.AuditFailOpen {
					t.Fatal("AuditFailOpen = false")
				}
			},
		},
		{
			name: "unknown section and key ignored gracefully",
			env: map[string]string{
				"GOBLESS_CA_PRIVATE_KEY_FILE": "/tmp/key",
				"GOBLESS_CA_SIGNER_TYPE":      "rsa",
				"GOBLESS_CA_DEFAULT_TTL":      "300",
				"GOBLESS_CA_MAX_TTL":          "600",
			},
			path: writeTempConfig(t, "[Unknown]\nthing=value\n[CA]\nignored=yes\n"),
			want: func(t *testing.T, cfg *Config) {
				t.Helper()
				if cfg.CA.PrivateKeyFile != "/tmp/key" {
					t.Fatalf("PrivateKeyFile = %q", cfg.CA.PrivateKeyFile)
				}
			},
		},
		{
			name:    "empty config file validation errors",
			path:    writeTempConfig(t, ""),
			wantErr: "invalid config",
		},
		{
			name: "signer type invalid",
			env: map[string]string{
				"GOBLESS_CA_PRIVATE_KEY_FILE": "/tmp/key",
				"GOBLESS_CA_SIGNER_TYPE":      "ed25519",
				"GOBLESS_CA_DEFAULT_TTL":      "300",
				"GOBLESS_CA_MAX_TTL":          "600",
			},
			wantErr: "SignerType",
		},
		{
			name: "PrivateKeyB64 invalid base64",
			env: map[string]string{
				"GOBLESS_CA_PRIVATE_KEY_B64": "not valid base64!!!",
				"GOBLESS_CA_SIGNER_TYPE":     "rsa",
				"GOBLESS_CA_DEFAULT_TTL":     "300",
				"GOBLESS_CA_MAX_TTL":         "600",
			},
			wantErr: "CA.PrivateKeyB64 is not valid base64",
		},
		{
			name: "PrivateKeyB64 valid base64 but not PEM",
			env: map[string]string{
				"GOBLESS_CA_PRIVATE_KEY_B64": base64.StdEncoding.EncodeToString([]byte("not pem")),
				"GOBLESS_CA_SIGNER_TYPE":     "rsa",
				"GOBLESS_CA_DEFAULT_TTL":     "300",
				"GOBLESS_CA_MAX_TTL":         "600",
			},
			wantErr: "CA.PrivateKeyB64 does not contain a valid PEM block",
		},
		{
			name: "PrivateKeyB64 valid base64 PEM",
			env: map[string]string{
				"GOBLESS_CA_PRIVATE_KEY_B64": base64.StdEncoding.EncodeToString(validPrivateKeyPEMForConfigTest),
				"GOBLESS_CA_SIGNER_TYPE":     "rsa",
				"GOBLESS_CA_DEFAULT_TTL":     "300",
				"GOBLESS_CA_MAX_TTL":         "600",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearGoblessEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			var logs bytes.Buffer
			oldWriter := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(oldWriter) })

			cfg, err := Load(tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if tt.wantLog != "" && !strings.Contains(logs.String(), tt.wantLog) {
				t.Fatalf("log = %q, want containing %q", logs.String(), tt.wantLog)
			}
			if tt.want != nil {
				tt.want(t, cfg)
			}
		})
	}
}

var validPrivateKeyPEMForConfigTest = []byte(`-----BEGIN PRIVATE KEY-----
AA==
-----END PRIVATE KEY-----
`)

func clearGoblessEnv(t *testing.T) {
	t.Helper()
	for _, env := range os.Environ() {
		name, _, _ := strings.Cut(env, "=")
		if strings.HasPrefix(name, "GOBLESS_") {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatalf("unset %s: %v", name, err)
			}
		}
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.cfg")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
