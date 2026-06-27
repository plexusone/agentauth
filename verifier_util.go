package agentauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// base64URLDecode decodes a base64url-encoded string.
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// jsonUnmarshal is a wrapper around json.Unmarshal.
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// IsJWT checks if a string looks like a JWT (3 dot-separated parts).
func IsJWT(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3
}

// DetectTokenProtocol attempts to detect the protocol from token claims.
// Returns empty string if unable to determine.
func DetectTokenProtocol(token string) Protocol {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}

	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		// AAuth tokens often have mission_id
		MissionID string `json:"mission_id"`
		// AAuth tokens use act claim for actor
		Act map[string]any `json:"act"`
		// ID-JAG uses specific grant types
		GrantType string `json:"grant_type"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	// AAuth tokens have mission_id or specific act structure
	if claims.MissionID != "" {
		return ProtocolAAuth
	}

	// Default to ID-JAG for standard assertions
	return ProtocolIDJAG
}
