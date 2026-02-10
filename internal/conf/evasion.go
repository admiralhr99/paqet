package conf

import (
	"fmt"
	"slices"
)

// Evasion holds DPI evasion configuration for Tier 1 fixes.
type Evasion struct {
	// EntropyMode controls first-packet camouflage.
	// "tls"  - Prepend TLS 1.3 ClientHello (best for Iran)
	// "ascii"- Prepend HTTP GET request
	// "auto" - Choose based on payload entropy
	// "none" - Disabled
	EntropyMode string `yaml:"entropy_mode"`

	// SNI is the Server Name Indication hostname used in the TLS ClientHello
	// and as the HTTP Host header. Should be a popular, non-blocked domain.
	SNI string `yaml:"sni"`

	// AuthSecret is the shared HMAC key for probe resistance.
	// Must be identical on client and server. Minimum 16 characters.
	AuthSecret string `yaml:"auth_secret"`

	// FallbackURL is the website to proxy unauthorized connections to (server only).
	// Must be a real HTTPS website that responds normally.
	FallbackURL string `yaml:"fallback_url"`
}

func (e *Evasion) setDefaults() {
	if e.EntropyMode == "" {
		e.EntropyMode = "none"
	}
	if e.SNI == "" {
		e.SNI = "www.microsoft.com"
	}
	if e.FallbackURL == "" {
		e.FallbackURL = "https://www.microsoft.com"
	}
}

func (e *Evasion) validate() []error {
	var errors []error

	validModes := []string{"tls", "ascii", "auto", "none"}
	if !slices.Contains(validModes, e.EntropyMode) {
		errors = append(errors, fmt.Errorf("evasion.entropy_mode must be one of: %v", validModes))
	}

	// If evasion is enabled, auth_secret is required
	if e.EntropyMode != "none" {
		if len(e.AuthSecret) == 0 {
			errors = append(errors, fmt.Errorf("evasion.auth_secret is required when evasion is enabled"))
		} else if len(e.AuthSecret) < 16 {
			errors = append(errors, fmt.Errorf("evasion.auth_secret must be at least 16 characters"))
		}
	}

	return errors
}

// Enabled returns true if any evasion feature is active.
func (e *Evasion) Enabled() bool {
	return e.EntropyMode != "" && e.EntropyMode != "none"
}
