package cert

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"security-project/common/crypto"
	"security-project/common/krb/protocol"
	"strings"
	"time"
)

// CertLoad 从指定路径加载证书文件，并解析为Certificate结构体。
func CertLoad(path string) (*Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cert Certificate
	if err := json.Unmarshal(b, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

func CertBodyBytes(cert *Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("nil cert")
	}
	var body certBody
	body.ID = cert.ID
	body.Issuer = cert.Issuer
	body.PublicKey.N = cert.PublicKey.N
	body.PublicKey.E = cert.PublicKey.E
	body.Expire = cert.Expire
	return json.Marshal(body)
}

// CertVerify 验证证书的有效性，包括过期时间和签名的正确性。
// 返回错误信息，如果验证成功则返回nil。
func CertVerify(cert *Certificate) error {
	if cert == nil {
		return protocol.ErrorFromCode(protocol.ErrCertLoadFail)
	}
	expire, err := time.Parse("2006-01-02", cert.Expire)
	if err != nil {
		return protocol.ErrorFromCode(protocol.ErrCertLoadFail)
	}
	if time.Now().After(expire.Add(24 * time.Hour)) {
		return protocol.ErrorFromCode(protocol.ErrCertExpired)
	}
	body, err := CertBodyBytes(cert)
	if err != nil {
		return protocol.ErrorFromCode(protocol.ErrCertLoadFail)
	}
	pub, err := cert.PublicKeyRSA()
	if err != nil {
		return protocol.ErrorFromCode(protocol.ErrCertSigInvalid)
	}
	sig, err := decodeSignature(cert.Sign)
	if err != nil {
		return protocol.ErrorFromCode(protocol.ErrCertSigInvalid)
	}
	sum := crypto.Sum256(body)
	if code := crypto.RsaVerifyDigest(sum[:], sig, pub); code != crypto.KRBOK {
		return protocol.ErrorFromCode(code)
	}
	return nil
}

// PublicKeyRSA 从证书的公钥信息中解析RSA公钥。
func (c *Certificate) PublicKeyRSA() (*crypto.RSAKey, error) {
	n, err := crypto.ParseBigIntHex(c.PublicKey.N)
	if err != nil {
		return nil, err
	}
	e, err := crypto.ParseBigIntHex(c.PublicKey.E)
	if err != nil {
		return nil, err
	}
	return &crypto.RSAKey{N: n, E: e}, nil
}

func CertFindByID(id string, certDB []*Certificate) *Certificate {
	for _, cert := range certDB {
		if cert != nil && cert.ID == id {
			return cert
		}
	}
	return nil
}

func decodeSignature(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty signature")
	}
	if len(s)%2 == 0 && crypto.IsHexString(s) {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 256 {
		return b, nil
	}
	return nil, errors.New("invalid signature format")
}
