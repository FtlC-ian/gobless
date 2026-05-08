// Package config handles configuration loading.
package config

import (
	"bufio"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Config contains GoBless runtime configuration.
type Config struct {
	CA struct {
		// Path to PEM file OR base64-encoded PEM content
		PrivateKeyFile string
		PrivateKeyB64  string
		// KMS key ID for asymmetric signing mode
		KMSKeyID string
		// Encrypted password for PEM key (KMS-encrypted, base64)
		EncryptedPassword string
		// DynamoDB table name for audit logging
		DynamoDBTable string
		// Key type: "rsa" or "kms" — determines which signer is used
		SignerType string
		// Default cert TTL in seconds
		DefaultTTL int
		// Max allowed TTL in seconds (hard cap)
		MaxTTL int
		// RSA minimum key size in bits (must be >= 2048, per #44)
		RSAMinKeyBits int
	}
	Principal struct {
		// Allowed principal names (comma-separated or repeated)
		Allowed []string
		// Whether to enforce IAM username == principal binding
		EnforceIAMBinding bool
		// Expected AWS account ID; if non-empty, IAMAccountID must match
		ExpectedAccountID string
		// AllowedCertTypes restricts which certificate types may be issued. When nil or empty, both user and host certificates are permitted. Set to ["user"] to prevent host cert issuance.
		AllowedCertTypes []string
	}
	Lambda struct {
		// AWS region
		Region string
		// Function name for self-reference
		FunctionName string
	}
	Logging struct {
		// Log level: debug, info, warn, error
		Level string
		// Whether to enable audit logging
		AuditEnabled bool
		// Audit fail-open: if true, signing proceeds on audit failure (DANGEROUS — loud warning required)
		AuditFailOpen bool
	}
}

// Load loads configuration from path, applies GOBLESS_<SECTION>_<KEY> environment
// overrides, then validates the final configuration.
func Load(path string) (*Config, error) {
	cfg := &Config{}

	if path != "" {
		if _, err := os.Stat(path); err == nil {
			if err := loadFile(cfg, path); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat config file %q: %w", path, err)
		}
	}

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	defaultConfig(cfg)

	if err := validate(cfg); err != nil {
		return nil, err
	}

	if cfg.Logging.AuditFailOpen {
		log.Printf("WARNING: audit fail-open is enabled; signing will proceed if audit logging fails")
	}

	return cfg, nil
}

func loadFile(cfg *Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config file %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	section := ""
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return fmt.Errorf("parse config file %q line %d: malformed section header", path, lineNo)
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("parse config file %q line %d: expected key=value", path, lineNo)
		}
		if err := applyValue(cfg, section, strings.TrimSpace(key), strings.TrimSpace(value), true); err != nil {
			return fmt.Errorf("parse config file %q line %d: %w", path, lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}
	return nil
}

func applyEnv(cfg *Config) error {
	for _, env := range os.Environ() {
		name, value, ok := strings.Cut(env, "=")
		if !ok || !strings.HasPrefix(name, "GOBLESS_") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(name, "GOBLESS_"), "_", 2)
		if len(parts) != 2 {
			continue
		}
		if err := applyValue(cfg, parts[0], parts[1], value, false); err != nil {
			return fmt.Errorf("parse environment variable %s: %w", name, err)
		}
	}
	return nil
}

func defaultConfig(cfg *Config) {
	if cfg.CA.RSAMinKeyBits == 0 {
		cfg.CA.RSAMinKeyBits = 2048
	}
}

func validate(cfg *Config) error {
	var errs []string

	if cfg.CA.PrivateKeyFile == "" && cfg.CA.PrivateKeyB64 == "" && cfg.CA.KMSKeyID == "" {
		errs = append(errs, "at least one of CA.PrivateKeyFile, CA.PrivateKeyB64, or CA.KMSKeyID is required")
	}
	if cfg.CA.SignerType != "rsa" && cfg.CA.SignerType != "kms" {
		errs = append(errs, `CA.SignerType must be "rsa" or "kms"`)
	}
	if cfg.CA.RSAMinKeyBits < 2048 {
		errs = append(errs, "CA.RSAMinKeyBits must be >= 2048")
	}
	if cfg.CA.PrivateKeyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(cfg.CA.PrivateKeyB64)
		if err != nil {
			errs = append(errs, "CA.PrivateKeyB64 is not valid base64")
		} else if block, _ := pem.Decode(decoded); block == nil {
			errs = append(errs, "CA.PrivateKeyB64 does not contain a valid PEM block")
		}
	}
	if cfg.CA.MaxTTL <= 0 {
		errs = append(errs, "CA.MaxTTL must be > 0")
	}
	if cfg.CA.DefaultTTL <= 0 {
		errs = append(errs, "CA.DefaultTTL must be > 0")
	} else if cfg.CA.MaxTTL > 0 && cfg.CA.DefaultTTL > cfg.CA.MaxTTL {
		errs = append(errs, "CA.DefaultTTL must be <= CA.MaxTTL")
	}
	if cfg.Logging.Level != "" {
		switch cfg.Logging.Level {
		case "debug", "info", "warn", "error":
		default:
			errs = append(errs, "Logging.Level must be one of debug, info, warn, or error")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config: %s", strings.Join(errs, "; "))
	}
	return nil
}

func applyValue(cfg *Config, section, key, value string, appendAllowed bool) error {
	section = normalize(section)
	key = normalize(key)

	switch section {
	case "CA":
		switch key {
		case "PRIVATE_KEY_FILE":
			cfg.CA.PrivateKeyFile = value
		case "PRIVATE_KEY_B64":
			cfg.CA.PrivateKeyB64 = value
		case "KMS_KEY_ID":
			cfg.CA.KMSKeyID = value
		case "DYNAMODB_TABLE":
			cfg.CA.DynamoDBTable = value
		case "ENCRYPTED_PASSWORD":
			cfg.CA.EncryptedPassword = value
		case "SIGNER_TYPE":
			cfg.CA.SignerType = strings.ToLower(value)
		case "DEFAULT_TTL":
			v, err := atoi(value)
			if err != nil {
				return fmt.Errorf("CA.DefaultTTL must be an integer: %w", err)
			}
			cfg.CA.DefaultTTL = v
		case "MAX_TTL":
			v, err := atoi(value)
			if err != nil {
				return fmt.Errorf("CA.MaxTTL must be an integer: %w", err)
			}
			cfg.CA.MaxTTL = v
		case "RSA_MIN_KEY_BITS":
			v, err := atoi(value)
			if err != nil {
				return fmt.Errorf("CA.RSAMinKeyBits must be an integer: %w", err)
			}
			cfg.CA.RSAMinKeyBits = v
		}
	case "PRINCIPAL":
		switch key {
		case "ALLOWED":
			if appendAllowed {
				cfg.Principal.Allowed = appendList(cfg.Principal.Allowed, value)
			} else {
				cfg.Principal.Allowed = appendList(nil, value)
			}
		case "ENFORCE_IAM_BINDING":
			v, err := atob(value)
			if err != nil {
				return fmt.Errorf("Principal.EnforceIAMBinding must be a boolean: %w", err)
			}
			cfg.Principal.EnforceIAMBinding = v
		case "EXPECTED_ACCOUNT_ID":
			cfg.Principal.ExpectedAccountID = value
		case "ALLOWED_CERT_TYPES":
			if appendAllowed {
				cfg.Principal.AllowedCertTypes = appendList(cfg.Principal.AllowedCertTypes, value)
			} else {
				cfg.Principal.AllowedCertTypes = appendList(nil, value)
			}
		}
	case "LAMBDA":
		switch key {
		case "REGION":
			cfg.Lambda.Region = value
		case "FUNCTION_NAME":
			cfg.Lambda.FunctionName = value
		}
	case "LOGGING":
		switch key {
		case "LEVEL":
			cfg.Logging.Level = strings.ToLower(value)
		case "AUDIT_ENABLED":
			v, err := atob(value)
			if err != nil {
				return fmt.Errorf("Logging.AuditEnabled must be a boolean: %w", err)
			}
			cfg.Logging.AuditEnabled = v
		case "AUDIT_FAIL_OPEN":
			v, err := atob(value)
			if err != nil {
				return fmt.Errorf("Logging.AuditFailOpen must be a boolean: %w", err)
			}
			cfg.Logging.AuditFailOpen = v
		}
	}
	return nil
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return strings.ToUpper(s)
}

func atoi(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}

func atob(s string) (bool, error) {
	return strconv.ParseBool(strings.TrimSpace(s))
}

func appendList(dst []string, value string) []string {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			dst = append(dst, item)
		}
	}
	return dst
}
