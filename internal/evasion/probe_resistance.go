package evasion

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"paqet/internal/flog"
)

const (
	// AuthTokenSize is the fixed size of the authentication token in bytes.
	// Layout: [timestamp:8][nonce:8][hmac:16] = 32 bytes
	AuthTokenSize = 32

	// DefaultTimestampTTL is the maximum allowed clock skew between client and server.
	DefaultTimestampTTL = 30 * time.Second

	// fallbackTimeout is the max time to wait when connecting to the fallback host.
	fallbackTimeout = 10 * time.Second

	// fallbackRelayTimeout is the max idle time for fallback relay connections.
	fallbackRelayTimeout = 60 * time.Second
)

// ProbeResistance implements REALITY-style active probe resistance.
// Invalid connections are seamlessly proxied to a legitimate website,
// making the server indistinguishable from a real web server to active probes.
type ProbeResistance struct {
	secret       []byte
	fallbackAddr string // "host:port" of fallback target
	timestampTTL time.Duration
}

// NewProbeResistance creates a new probe resistance module.
// secret: shared HMAC key (must match between client and server)
// fallbackURL: URL for unauthorized connections (e.g. "https://www.microsoft.com")
func NewProbeResistance(secret string, fallbackURL string) *ProbeResistance {
	// Derive a 32-byte key from the user-provided secret using SHA-256
	h := sha256.Sum256([]byte(secret))

	// Parse fallback address
	fallbackAddr := parseFallbackAddr(fallbackURL)

	return &ProbeResistance{
		secret:       h[:],
		fallbackAddr: fallbackAddr,
		timestampTTL: DefaultTimestampTTL,
	}
}

// parseFallbackAddr extracts "host:port" from a URL string.
func parseFallbackAddr(url string) string {
	if url == "" {
		return "www.microsoft.com:443"
	}

	// Strip scheme
	host := url
	if len(host) > 8 && host[:8] == "https://" {
		host = host[8:]
	} else if len(host) > 7 && host[:7] == "http://" {
		host = host[7:]
	}

	// Strip trailing path
	for i := 0; i < len(host); i++ {
		if host[i] == '/' {
			host = host[:i]
			break
		}
	}

	// Add default port if missing
	hasPort := false
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			hasPort = true
			break
		}
		if host[i] == ']' { // IPv6
			break
		}
	}
	if !hasPort {
		host = host + ":443"
	}

	return host
}

// GenerateAuthToken creates a 32-byte HMAC authentication token.
//
// Token layout (32 bytes total):
//
//	[0:8]   Unix timestamp in milliseconds (big-endian uint64)
//	[8:16]  Cryptographic random nonce
//	[16:32] HMAC-SHA256(secret, timestamp || nonce) truncated to 16 bytes
func (p *ProbeResistance) GenerateAuthToken() ([]byte, error) {
	token := make([]byte, AuthTokenSize)

	// Timestamp: 8 bytes, big-endian milliseconds
	ts := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(token[0:8], ts)

	// Nonce: 8 random bytes
	if _, err := rand.Read(token[8:16]); err != nil {
		return nil, fmt.Errorf("probe: failed to generate nonce: %w", err)
	}

	// HMAC: SHA256(secret, timestamp || nonce), truncated to 16 bytes
	mac := hmac.New(sha256.New, p.secret)
	mac.Write(token[0:16])
	fullMAC := mac.Sum(nil) // 32 bytes
	copy(token[16:32], fullMAC[:16])

	return token, nil
}

// ValidateAuthToken checks if a 32-byte token is valid.
// Uses constant-time comparison to prevent timing side-channels.
func (p *ProbeResistance) ValidateAuthToken(token []byte) bool {
	if len(token) < AuthTokenSize {
		return false
	}

	// Check timestamp within ±TTL window
	tsMillis := int64(binary.BigEndian.Uint64(token[0:8]))
	nowMillis := time.Now().UnixMilli()
	diff := nowMillis - tsMillis
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Millisecond > p.timestampTTL {
		return false
	}

	// Recompute HMAC and compare in constant time
	mac := hmac.New(sha256.New, p.secret)
	mac.Write(token[0:16])
	expected := mac.Sum(nil)

	return hmac.Equal(token[16:32], expected[:16])
}

// PrependAuthToken generates a token and prepends it to the payload.
// Client-side: call this before entropy wrapping.
func (p *ProbeResistance) PrependAuthToken(payload []byte) ([]byte, error) {
	token, err := p.GenerateAuthToken()
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, AuthTokenSize+len(payload))
	result = append(result, token...)
	result = append(result, payload...)
	return result, nil
}

// ExtractAndValidate extracts the auth token, validates it, and returns the remaining payload.
// Server-side: call this after entropy unwrapping.
// Returns: payload (without token), valid bool, error
func (p *ProbeResistance) ExtractAndValidate(data []byte) ([]byte, bool, error) {
	if len(data) < AuthTokenSize {
		return nil, false, fmt.Errorf("probe: data too small for auth token (%d < %d)", len(data), AuthTokenSize)
	}

	token := data[:AuthTokenSize]
	payload := data[AuthTokenSize:]
	valid := p.ValidateAuthToken(token)

	return payload, valid, nil
}

// HandleUnauthorized proxies an unauthenticated raw connection to the fallback website.
// This makes the server look like a legitimate web server to DPI active probes.
//
// The firstData parameter contains any bytes already read from the connection
// (e.g. the invalid auth attempt or probe data), which are forwarded to the
// fallback server to maintain the illusion of a real connection.
func (p *ProbeResistance) HandleUnauthorized(conn net.Conn, firstData []byte) {
	defer conn.Close()

	// Connect to fallback target
	fallbackConn, err := net.DialTimeout("tcp", p.fallbackAddr, fallbackTimeout)
	if err != nil {
		flog.Debugf("probe: fallback dial to %s failed: %v", p.fallbackAddr, err)
		return
	}
	defer fallbackConn.Close()

	// Forward the initial data (the probe's first message) to fallback
	if len(firstData) > 0 {
		fallbackConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := fallbackConn.Write(firstData); err != nil {
			flog.Debugf("probe: failed to forward initial data to fallback: %v", err)
			return
		}
		fallbackConn.SetWriteDeadline(time.Time{})
	}

	// Bidirectional relay with timeouts
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		conn.SetReadDeadline(time.Now().Add(fallbackRelayTimeout))
		fallbackConn.SetWriteDeadline(time.Now().Add(fallbackRelayTimeout))
		io.Copy(fallbackConn, conn)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		fallbackConn.SetReadDeadline(time.Now().Add(fallbackRelayTimeout))
		conn.SetWriteDeadline(time.Now().Add(fallbackRelayTimeout))
		io.Copy(conn, fallbackConn)
	}()

	// Wait for one direction to finish, then close both
	<-done
}
