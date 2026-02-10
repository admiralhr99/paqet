package evasion

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

// EntropyManager wraps the first KCP packet with a protocol-conforming prefix
// to defeat Iran DPI entropy analysis (popcount 3.4-4.6 detection) and
// protocol whitelisting (only HTTP/HTTPS/DNS allowed at TIC gateway).
//
// The TLS mode prepends a complete, Wireshark-decodable TLS 1.3 ClientHello.
// The server strips this prefix to recover the original KCP payload.
type EntropyManager struct {
	mode string // "tls", "ascii", "auto", "none"
	sni  string // SNI hostname for TLS ClientHello
	mu   sync.Mutex
}

// NewEntropyManager creates a new entropy manager.
// mode: "tls" (recommended for Iran), "ascii", "auto", "none"
// sni: Server Name Indication hostname (e.g. "www.microsoft.com")
func NewEntropyManager(mode, sni string) *EntropyManager {
	if mode == "" {
		mode = "tls"
	}
	if sni == "" {
		sni = "www.microsoft.com"
	}
	return &EntropyManager{mode: mode, sni: sni}
}

// WrapFirstPacket prepends a protocol-conforming camouflage prefix to the first packet.
// Client-side only. Must be called exactly once per connection.
func (e *EntropyManager) WrapFirstPacket(payload []byte) ([]byte, error) {
	switch e.mode {
	case "tls":
		return e.wrapTLS(payload)
	case "ascii":
		return e.wrapASCII(payload)
	case "auto":
		if isHighEntropy(payload) {
			return e.wrapTLS(payload)
		}
		return e.wrapASCII(payload)
	case "none":
		return payload, nil
	default:
		return payload, nil
	}
}

// UnwrapFirstPacket removes the camouflage prefix from the first received packet.
// Server-side only. Must be called exactly once per connection.
func (e *EntropyManager) UnwrapFirstPacket(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("entropy: packet too small (%d bytes)", len(data))
	}

	// Detect TLS record: ContentType=Handshake(0x16), Version=0x03XX
	if data[0] == 0x16 && data[1] == 0x03 {
		return e.unwrapTLS(data)
	}

	// Detect HTTP: starts with common method keywords
	if len(data) >= 4 {
		prefix4 := string(data[:4])
		if prefix4 == "GET " || prefix4 == "POST" || prefix4 == "HTTP" || prefix4 == "HEAD" {
			return e.unwrapASCII(data)
		}
	}

	// No recognized prefix — return raw (backwards compat or "none" mode)
	return data, nil
}

// wrapTLS builds a complete TLS 1.3 ClientHello record and prepends it to payload.
//
// Structure per RFC 8446 & tls13.xargs.org:
//
//	Record Layer: 16 03 01 [len:2]
//	Handshake:    01 [len:3]
//	  ClientHello:
//	    legacy_version:              03 03
//	    random:                      [32 bytes]
//	    legacy_session_id:           20 [32 bytes]  (middlebox compat)
//	    cipher_suites:               00 06 13 01 13 02 13 03
//	    legacy_compression_methods:  01 00
//	    extensions:                  [len:2]
//	      SNI (0x0000)
//	      Supported Groups (0x000a)
//	      Signature Algorithms (0x000d)
//	      Supported Versions (0x002b)
//	      Key Share (0x0033)
func (e *EntropyManager) wrapTLS(payload []byte) ([]byte, error) {
	// Generate random values
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil, fmt.Errorf("entropy: failed to generate client random: %w", err)
	}

	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, fmt.Errorf("entropy: failed to generate session ID: %w", err)
	}

	fakeKeyShare := make([]byte, 32)
	if _, err := rand.Read(fakeKeyShare); err != nil {
		return nil, fmt.Errorf("entropy: failed to generate key share: %w", err)
	}

	// === Build Extensions ===
	extensions := e.buildExtensions(fakeKeyShare)

	// === Build ClientHello body (after handshake type+length) ===
	var ch []byte

	// legacy_version: TLS 1.2
	ch = append(ch, 0x03, 0x03)

	// random: 32 bytes
	ch = append(ch, clientRandom...)

	// legacy_session_id: length-prefixed (1 byte length + 32 bytes)
	ch = append(ch, 0x20) // 32 bytes
	ch = append(ch, sessionID...)

	// cipher_suites: TLS 1.3 suites
	ch = append(ch,
		0x00, 0x06, // 6 bytes of cipher suite data
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
		0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
	)

	// legacy_compression_methods: null only
	ch = append(ch,
		0x01, // 1 byte of compression methods
		0x00, // null compression
	)

	// extensions length (2 bytes) + extensions data
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(extensions)))
	ch = append(ch, extLen...)
	ch = append(ch, extensions...)

	// === Build Handshake message ===
	var handshake []byte
	handshake = append(handshake, 0x01) // HandshakeType: ClientHello

	// 3-byte length of ClientHello body
	hsLen := len(ch)
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, ch...)

	// === Build TLS Record Layer ===
	var record []byte
	record = append(record, 0x16)       // ContentType: Handshake
	record = append(record, 0x03, 0x01) // Version: TLS 1.0 (per RFC 8446 for initial ClientHello)

	// 2-byte record length
	recLen := len(handshake)
	record = append(record, byte(recLen>>8), byte(recLen))
	record = append(record, handshake...)

	// Prepend TLS record to actual KCP payload
	result := make([]byte, 0, len(record)+len(payload))
	result = append(result, record...)
	result = append(result, payload...)

	return result, nil
}

// buildExtensions constructs the TLS 1.3 ClientHello extensions block.
// These extensions are mandatory for a believable TLS 1.3 ClientHello:
//   - SNI: identifies target hostname
//   - Supported Groups: which EC curves we support
//   - Signature Algorithms: which sig algos we support
//   - Supported Versions: declares TLS 1.3 support (the real version negotiation)
//   - Key Share: ephemeral x25519 public key
func (e *EntropyManager) buildExtensions(keySharePubKey []byte) []byte {
	var ext []byte

	// --- Extension: Server Name Indication (0x0000) ---
	sniBytes := []byte(e.sni)
	sniListEntry := make([]byte, 0, 3+len(sniBytes))
	sniListEntry = append(sniListEntry, 0x00) // HostNameType: host_name
	sniListEntry = append(sniListEntry, byte(len(sniBytes)>>8), byte(len(sniBytes)))
	sniListEntry = append(sniListEntry, sniBytes...)

	sniList := make([]byte, 0, 2+len(sniListEntry))
	sniList = append(sniList, byte(len(sniListEntry)>>8), byte(len(sniListEntry)))
	sniList = append(sniList, sniListEntry...)

	ext = append(ext, 0x00, 0x00) // Extension type: server_name
	ext = append(ext, byte(len(sniList)>>8), byte(len(sniList)))
	ext = append(ext, sniList...)

	// --- Extension: EC Point Formats (0x000b) ---
	ext = append(ext,
		0x00, 0x0b, // Extension type: ec_point_formats
		0x00, 0x04, // 4 bytes of data
		0x03, // 3 formats follow
		0x00, // uncompressed
		0x01, // ansiX962_compressed_prime
		0x02, // ansiX962_compressed_char2
	)

	// --- Extension: Supported Groups (0x000a) ---
	ext = append(ext,
		0x00, 0x0a, // Extension type: supported_groups
		0x00, 0x0a, // 10 bytes of extension data
		0x00, 0x08, // 8 bytes of curve list
		0x00, 0x1d, // x25519
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
		0x00, 0x19, // secp521r1
	)

	// --- Extension: Session Ticket (0x0023) ---
	ext = append(ext,
		0x00, 0x23, // Extension type: session_ticket
		0x00, 0x00, // 0 bytes (no ticket)
	)

	// --- Extension: Encrypt Then MAC (0x0016) ---
	ext = append(ext,
		0x00, 0x16, // Extension type: encrypt_then_mac
		0x00, 0x00, // 0 bytes
	)

	// --- Extension: Extended Master Secret (0x0017) ---
	ext = append(ext,
		0x00, 0x17, // Extension type: extended_master_secret
		0x00, 0x00, // 0 bytes
	)

	// --- Extension: Signature Algorithms (0x000d) ---
	ext = append(ext,
		0x00, 0x0d, // Extension type: signature_algorithms
		0x00, 0x14, // 20 bytes of data
		0x00, 0x12, // 18 bytes of algorithm list
		0x04, 0x03, // ECDSA-SECP256r1-SHA256
		0x05, 0x03, // ECDSA-SECP384r1-SHA384
		0x06, 0x03, // ECDSA-SECP521r1-SHA512
		0x08, 0x04, // RSA-PSS-RSAE-SHA256
		0x08, 0x05, // RSA-PSS-RSAE-SHA384
		0x08, 0x06, // RSA-PSS-RSAE-SHA512
		0x04, 0x01, // RSA-PKCS1-SHA256
		0x05, 0x01, // RSA-PKCS1-SHA384
		0x06, 0x01, // RSA-PKCS1-SHA512
	)

	// --- Extension: Supported Versions (0x002b) ---
	// CRITICAL: This is what makes it TLS 1.3
	ext = append(ext,
		0x00, 0x2b, // Extension type: supported_versions
		0x00, 0x03, // 3 bytes of data
		0x02,       // 2 bytes of version list
		0x03, 0x04, // TLS 1.3
	)

	// --- Extension: PSK Key Exchange Modes (0x002d) ---
	ext = append(ext,
		0x00, 0x2d, // Extension type: psk_key_exchange_modes
		0x00, 0x02, // 2 bytes of data
		0x01, // 1 mode follows
		0x01, // PSK with (EC)DHE
	)

	// --- Extension: Key Share (0x0033) ---
	// x25519 public key: 32 bytes
	keyShareEntry := make([]byte, 0, 4+len(keySharePubKey))
	keyShareEntry = append(keyShareEntry, 0x00, 0x1d) // x25519
	keyShareEntry = append(keyShareEntry, byte(len(keySharePubKey)>>8), byte(len(keySharePubKey)))
	keyShareEntry = append(keyShareEntry, keySharePubKey...)

	keyShareData := make([]byte, 0, 2+len(keyShareEntry))
	keyShareData = append(keyShareData, byte(len(keyShareEntry)>>8), byte(len(keyShareEntry)))
	keyShareData = append(keyShareData, keyShareEntry...)

	ext = append(ext, 0x00, 0x33) // Extension type: key_share
	ext = append(ext, byte(len(keyShareData)>>8), byte(len(keyShareData)))
	ext = append(ext, keyShareData...)

	return ext
}

// unwrapTLS strips the TLS record + ClientHello from the front of data.
func (e *EntropyManager) unwrapTLS(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("entropy: TLS record too short")
	}

	// Parse TLS record layer
	// data[0] = ContentType (0x16 = Handshake)
	// data[1:3] = Version
	// data[3:5] = Length of TLS record payload
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	totalTLSLen := 5 + recordLen

	if len(data) < totalTLSLen {
		return nil, fmt.Errorf("entropy: incomplete TLS record (need %d, have %d)", totalTLSLen, len(data))
	}

	// Everything after the TLS record is our KCP payload
	remaining := data[totalTLSLen:]
	if len(remaining) == 0 {
		return nil, fmt.Errorf("entropy: no KCP payload after TLS record")
	}

	return remaining, nil
}

// wrapASCII prepends a fake HTTP GET request to defeat ASCII ratio heuristics.
func (e *EntropyManager) wrapASCII(payload []byte) ([]byte, error) {
	httpPrefix := []byte(
		"GET / HTTP/1.1\r\n" +
			"Host: " + e.sni + "\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n" +
			"Accept: text/html,application/xhtml+xml\r\n" +
			"Accept-Language: en-US,en;q=0.9\r\n" +
			"Connection: keep-alive\r\n" +
			"\r\n",
	)

	result := make([]byte, 0, len(httpPrefix)+len(payload))
	result = append(result, httpPrefix...)
	result = append(result, payload...)
	return result, nil
}

// unwrapASCII strips the HTTP header prefix from data.
func (e *EntropyManager) unwrapASCII(data []byte) ([]byte, error) {
	// Find \r\n\r\n (end of HTTP headers)
	for i := 0; i <= len(data)-4; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			remaining := data[i+4:]
			if len(remaining) == 0 {
				return nil, fmt.Errorf("entropy: no KCP payload after HTTP header")
			}
			return remaining, nil
		}
	}
	return nil, fmt.Errorf("entropy: malformed HTTP prefix (no header terminator)")
}

// isHighEntropy checks if payload has entropy in the DPI detection range.
// Iran DPI flags payloads with popcount (set bits per byte) in range 3.4-4.6.
func isHighEntropy(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	totalBits := 0
	for _, b := range data {
		totalBits += popcount(b)
	}

	avgBits := float64(totalBits) / float64(len(data))
	return avgBits >= 3.4 && avgBits <= 4.6
}

// popcount returns the number of set bits in a byte.
func popcount(b byte) int {
	// Brian Kernighan's bit counting
	count := 0
	for b != 0 {
		b &= b - 1
		count++
	}
	return count
}
