package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type RSAKeyJSON struct {
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d,omitempty"`
}

// LoadConfiguredKey8 从指定路径或内联字符串加载一个8字节DES密钥。
func LoadConfiguredKey8(path string, inline string, label string) ([8]byte, error) {
	var out [8]byte
	if strings.TrimSpace(inline) != "" {
		key, ok := ParseKeyBytes([]byte(inline))
		if !ok {
			return out, fmt.Errorf("%s key inline value is invalid", label)
		}
		copy(out[:], key)
		return out, nil
	}
	if strings.TrimSpace(path) == "" {
		return out, fmt.Errorf("%s key path or inline key is required", label)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return out, fmt.Errorf("read %s key %q: %w", label, path, err)
	}
	if len(b) == 8 {
		copy(out[:], b)
		return out, nil
	}
	key, ok := ParseKeyBytes(b)
	if !ok {
		return out, fmt.Errorf("%s key %q is not 8-byte raw, hex, base64, or key JSON", label, path)
	}
	copy(out[:], key)
	return out, nil
}

// ParseKeyBytes 从原始字节中解析8字节密钥，支持raw、hex、base64和{"key": "..."} JSON。
func ParseKeyBytes(raw []byte) ([]byte, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false
	}
	if raw[0] == '{' {
		var doc struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(raw, &doc); err == nil && doc.Key != "" {
			if decoded, ok := DecodeKeyString(doc.Key); ok {
				return decoded, true
			}
		}
	}
	if decoded, ok := DecodeKeyString(string(raw)); ok {
		return decoded, true
	}
	return nil, false
}

func DecodeKeyString(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) >= 8 {
		return decoded[:8], true
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil && len(decoded) >= 8 {
		return decoded[:8], true
	}
	return nil, false
}

// LoadRSAPrivateKey 从JSON文件加载RSA私钥。
func LoadRSAPrivateKey(path string) (*RSAKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc RSAKeyJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	n, err := ParseBigIntHex(doc.N)
	if err != nil {
		return nil, err
	}
	e, err := ParseBigIntHex(doc.E)
	if err != nil {
		return nil, err
	}
	d, err := ParseBigIntHex(doc.D)
	if err != nil {
		return nil, err
	}
	return &RSAKey{N: n, E: e, D: d}, nil
}

// ParseBigIntHex 尝试将字符串解析为大整数，支持十六进制和十进制。
func ParseBigIntHex(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty big integer")
	}
	if v, ok := new(big.Int).SetString(s, 16); ok {
		return v, nil
	}
	if v, ok := new(big.Int).SetString(s, 10); ok {
		return v, nil
	}
	return nil, fmt.Errorf("invalid integer: %s", s)
}

func IsHexString(s string) bool {
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}
