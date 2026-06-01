//go:build ignore

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	defaultIssuer      = "LOCAL_DEBUG_CA"
	defaultExpire      = "2036-12-31"
	defaultClientCount = 4
	rsaBits            = 2048
	rsaPublicExponent  = 65537
)

var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

// 小素数筛，用于 Miller-Rabin 素性测试前的快速排除。包含了所有小于100的素数。
var smallPrimeMap = []int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23,
	29, 31, 37, 41, 43, 47, 53, 59, 61,
	67, 71, 73, 79, 83, 89, 97,
}

type keyDoc struct {
	N string `json:"n"`
	E string `json:"e"`
	D string `json:"d,omitempty"`
}

type publicKeyDoc struct {
	N string `json:"n"`
	E string `json:"e"`
}

type certDoc struct {
	ID        string       `json:"id"`
	Issuer    string       `json:"issuer"`
	PublicKey publicKeyDoc `json:"public_key"`
	Expire    string       `json:"expire"`
	Sign      string       `json:"sign,omitempty"`
}

type rsaPrivateKey struct {
	N *big.Int
	E *big.Int
	D *big.Int
}

// generatedIdentity 是 generateIdentity 函数的返回类型，包含生成的密钥和证书文档。
type generatedIdentity struct {
	EntityID   string
	PrivateDoc keyDoc
	PublicDoc  publicKeyDoc
	Cert       certDoc
}

type positiveInt struct {
	value int
	field string
}

func (p *positiveInt) Set(raw string) error {
	value, err := parsePositiveInt(raw, p.field)
	if err != nil {
		return err
	}
	p.value = value
	return nil
}

func (p *positiveInt) String() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d", p.value)
}

func main() {
	rootDefault, err := repoRoot()
	if err != nil {
		fatal(err)
	}

	clients := &positiveInt{value: defaultClientCount, field: "clients"}
	activeClient := &positiveInt{value: 1, field: "active-client"}
	root := flag.String("root", rootDefault, "project root, default: repository root")
	issuer := flag.String("issuer", defaultIssuer, "issuer")
	expire := flag.String("expire", defaultExpire, "expire date YYYY-MM-DD")
	noActiveAlias := flag.Bool("no-active-alias", false, "do not update client/keys/client_priv.json and client/certs/cert_client.json")
	writePublic := flag.Bool("write-public-json", false, "also write *_pub.json files for debugging")
	flag.Var(clients, "clients", "number of CLIENT_N identities to generate")
	flag.Var(activeClient, "active-client", "CLIENT_N copied to client/keys/client_priv.json and client/certs/cert_client.json")
	flag.Parse()

	if activeClient.value > clients.value {
		fatal(errors.New("--active-client must be less than or equal to --clients"))
	}

	projectRoot, err := filepath.Abs(*root)
	if err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		fatal(err)
	}

	fmt.Printf("Project root: %s\n", projectRoot)
	fmt.Printf("Issuer:       %s\n", *issuer)
	fmt.Printf("Expire:       %s\n\n", *expire)

	fmt.Println("Generating V identity...")
	if err := writeVIdentity(projectRoot, *issuer, *expire, *writePublic); err != nil {
		fatal(err)
	}

	fmt.Println("\nGenerating client identities...")
	var activePrivatePath string
	var activeCertPath string
	for i := 1; i <= clients.value; i++ {
		privatePath, certPath, err := writeClientIdentity(projectRoot, clientID(i), *issuer, *expire, *writePublic)
		if err != nil {
			fatal(err)
		}
		if i == activeClient.value {
			activePrivatePath = privatePath
			activeCertPath = certPath
		}
	}

	if !*noActiveAlias {
		fmt.Println("\nUpdating active client alias...")
		if err := writeActiveAlias(projectRoot, activeClient.value, activePrivatePath, activeCertPath); err != nil {
			fatal(err)
		}
	}

	fmt.Println("\nDone. Generated only the V/Client certificate files required by the APP signature flow.")
}

func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("resolve source path failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..")), nil
}

func parsePositiveInt(raw string, field string) (int, error) {
	var value int
	if _, err := fmt.Sscanf(strings.TrimSpace(raw), "%d", &value); err != nil {
		return 0, fmt.Errorf("%s must be an integer: %s", field, raw)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be greater than 0", field)
	}
	return value, nil
}

func clientID(number int) string {
	return fmt.Sprintf("CLIENT_%d", number)
}

func clientNumber(id string) (int, error) {
	const prefix = "CLIENT_"
	if !strings.HasPrefix(id, prefix) {
		return 0, fmt.Errorf("unsupported client id format: %s", id)
	}
	return parsePositiveInt(strings.TrimPrefix(id, prefix), "client number")
}

func writeVIdentity(root string, issuer string, expire string, writePublic bool) error {
	identity, err := generateIdentity("verify_server", issuer, expire)
	if err != nil {
		return err
	}
	privatePath := filepath.Join(root, "keys", "v_priv.json")
	certPath := filepath.Join(root, "certs", "v_cert.json")

	if err := writeJSON(privatePath, identity.PrivateDoc, 0o600); err != nil {
		return err
	}
	if err := writeJSON(certPath, identity.Cert, 0o644); err != nil {
		return err
	}
	fmt.Printf("%-14s private: %s\n", identity.EntityID, privatePath)
	fmt.Printf("%-14s cert:    %s\n", identity.EntityID, certPath)

	if writePublic {
		publicPath := filepath.Join(root, "keys", "v_pub.json")
		if err := writeJSON(publicPath, identity.PublicDoc, 0o644); err != nil {
			return err
		}
		fmt.Printf("%-14s public:  %s\n", identity.EntityID, publicPath)
	}
	return nil
}

func writeClientIdentity(root string, id string, issuer string, expire string, writePublic bool) (string, string, error) {
	number, err := clientNumber(id)
	if err != nil {
		return "", "", err
	}
	identity, err := generateIdentity(id, issuer, expire)
	if err != nil {
		return "", "", err
	}

	privatePath := filepath.Join(root, "client", "keys", fmt.Sprintf("client%d_priv.json", number))
	localCertPath := filepath.Join(root, "client", "certs", fmt.Sprintf("cert_client%d.json", number))
	serverCertPath := filepath.Join(root, "certs", fmt.Sprintf("client%d_cert.json", number))

	if err := writeJSON(privatePath, identity.PrivateDoc, 0o600); err != nil {
		return "", "", err
	}
	if err := writeJSON(localCertPath, identity.Cert, 0o644); err != nil {
		return "", "", err
	}
	if err := writeJSON(serverCertPath, identity.Cert, 0o644); err != nil {
		return "", "", err
	}

	fmt.Printf("%-14s private: %s\n", id, privatePath)
	fmt.Printf("%-14s cert:    %s\n", id, localCertPath)
	fmt.Printf("%-14s shared:  %s\n", id, serverCertPath)

	if writePublic {
		publicPath := filepath.Join(root, "client", "keys", fmt.Sprintf("client%d_pub.json", number))
		if err := writeJSON(publicPath, identity.PublicDoc, 0o644); err != nil {
			return "", "", err
		}
		fmt.Printf("%-14s public:  %s\n", id, publicPath)
	}

	return privatePath, localCertPath, nil
}

func writeActiveAlias(root string, activeClient int, privatePath string, certPath string) error {
	activePrivate := filepath.Join(root, "client", "keys", "client_priv.json")
	activeCert := filepath.Join(root, "client", "certs", "cert_client.json")
	if err := copyFile(privatePath, activePrivate, 0o600); err != nil {
		return err
	}
	if err := copyFile(certPath, activeCert, 0o644); err != nil {
		return err
	}
	fmt.Printf("CLIENT_%-7d alias:   %s\n", activeClient, activePrivate)
	fmt.Printf("CLIENT_%-7d alias:   %s\n", activeClient, activeCert)
	return nil
}

func generateIdentity(entityID string, issuer string, expire string) (generatedIdentity, error) {
	privateDoc, publicDoc, privateKey, err := generateRSAKeypair()
	if err != nil {
		return generatedIdentity{}, err
	}
	cert, err := createCertificate(entityID, issuer, expire, publicDoc, privateKey)
	if err != nil {
		return generatedIdentity{}, err
	}
	return generatedIdentity{
		EntityID:   entityID,
		PrivateDoc: privateDoc,
		PublicDoc:  publicDoc,
		Cert:       cert,
	}, nil
}

// generateRSAKeypair 生成一个 RSA 密钥对，返回私钥文档、公钥文档、私钥结构体和错误。对齐 script/rsa_logic.h 的 key_generate 函数实现。
func generateRSAKeypair() (keyDoc, publicKeyDoc, rsaPrivateKey, error) {
	e := big.NewInt(rsaPublicExponent)
	one := big.NewInt(1)

	for {
		p, err := generatePrimeBySearch(rsaBits / 2)
		if err != nil {
			return keyDoc{}, publicKeyDoc{}, rsaPrivateKey{}, err
		}
		q, err := generatePrimeBySearch(rsaBits / 2)
		if err != nil {
			return keyDoc{}, publicKeyDoc{}, rsaPrivateKey{}, err
		}

		// 确保 p 和 q 不相等，且 n 的位数正确。
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		if n.BitLen() != rsaBits {
			continue
		}

		pMinus1 := new(big.Int).Sub(p, one)
		qMinus1 := new(big.Int).Sub(q, one)

		//欧拉函数 phi(n) = (p-1)(q-1)
		phi := eularTotient(pMinus1, qMinus1)
		//算模逆元 d，使得 ed ≡ 1 (mod phi(n))
		d := modInverse(e, phi)
		if d.Sign() <= 0 {
			continue
		}

		privateDoc := keyDoc{
			N: hexInt(n, 512),
			E: hexInt(e, 6),
			D: hexInt(d, 512),
		}
		publicDoc := publicKeyDoc{
			N: privateDoc.N,
			E: privateDoc.E,
		}
		return privateDoc, publicDoc, rsaPrivateKey{
			N: n,
			E: e,
			D: d,
		}, nil
	}
}

// eularTotient 计算欧拉函数 phi(n) = (p-1)(q-1)，其中 pMinus1 = p-1，qMinus1 = q-1。
func eularTotient(pMinus1 *big.Int, qMinus1 *big.Int) *big.Int {
	return new(big.Int).Mul(pMinus1, qMinus1)
}

// generatePrimeBySearch 对齐 script/rsa_logic.h：先生成随机奇数，再每次 +2 直到通过素性测试。
func generatePrimeBySearch(bits int) (*big.Int, error) {
	p, err := generateRandomBigInt(bits)
	if err != nil {
		return nil, err
	}
	two := big.NewInt(2)
	for !isPrime(p) {
		p.Add(p, two)
		if p.BitLen() != bits {
			return generatePrimeBySearch(bits)
		}
	}
	return p, nil
}

// generateRandomBigInt 对齐 script/rsa_math.h：按64位随机数拼接，设置最高位和最低位。
func generateRandomBigInt(bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, errors.New("random integer bit length must be at least 2")
	}
	out := big.NewInt(0)
	fullWords := bits / 64
	for i := 0; i < fullWords; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		out.Lsh(out, 64)
		out.Or(out, new(big.Int).SetUint64(binary.BigEndian.Uint64(buf)))
	}
	remainingBits := bits % 64
	if remainingBits > 0 {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		value := binary.BigEndian.Uint64(buf)
		value &= (uint64(1) << remainingBits) - 1
		out.Lsh(out, uint(remainingBits))
		out.Or(out, new(big.Int).SetUint64(value))
	}
	out.Or(out, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	out.Or(out, big.NewInt(1))
	return out, nil
}

// isPrime 先做小素数筛，再用手写 Miller-Rabin。
func isPrime(n *big.Int) bool {
	if n.Cmp(big.NewInt(2)) < 0 {
		return false
	}
	for _, prime := range smallPrimeMap {
		p := big.NewInt(prime)
		if n.Cmp(p) == 0 {
			return true
		}
		if new(big.Int).Mod(n, p).Sign() == 0 {
			return false
		}
	}
	return millerRabin(n, 8)
}

// millerRabin 实现 Miller-Rabin 素性测试，testTime 是测试轮数，返回 n 是否通过测试。
func millerRabin(n *big.Int, testTime int) bool {
	two := big.NewInt(2)
	three := big.NewInt(3)
	if n.Cmp(three) < 0 || new(big.Int).Mod(n, two).Sign() == 0 {
		return n.Cmp(two) == 0
	}
	if new(big.Int).Mod(n, three).Sign() == 0 {
		return n.Cmp(three) == 0
	}

	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(n, one)
	u := new(big.Int).Set(nMinus1)
	t := 0
	for new(big.Int).Mod(u, two).Sign() == 0 {
		u.Div(u, two)
		t++
	}

	nMinus3 := new(big.Int).Sub(n, three)
	for i := 0; i < testTime; i++ {
		a, err := generateRandomBigInt(n.BitLen())
		if err != nil {
			return false
		}
		a.Mod(a, nMinus3)
		a.Add(a, two)

		v := quickPow(a, u, n)
		if v.Cmp(one) == 0 {
			continue
		}
		s := 0
		for ; s < t; s++ {
			if v.Cmp(nMinus1) == 0 {
				break
			}
			v.Mul(v, v)
			v.Mod(v, n)
		}
		if s == t {
			return false
		}
	}
	return true
}

// createCertificate 生成证书文档，先构造不含签名的证书主体，计算其字节表示，再用 RSA 私钥签名，最后将签名添加到证书主体中。
func createCertificate(entityID string, issuer string, expire string, publicDoc publicKeyDoc, privateKey rsaPrivateKey) (certDoc, error) {
	body := certDoc{
		ID:        entityID,
		Issuer:    issuer,
		PublicKey: publicDoc,
		Expire:    expire,
	}
	bodyBytes, err := certBodyBytes(body)
	if err != nil {
		return certDoc{}, err
	}
	signature, err := rsaSignSHA256PKCS1v15(bodyBytes, privateKey)
	if err != nil {
		return certDoc{}, err
	}
	body.Sign = fmt.Sprintf("%x", signature)
	return body, nil
}

func certBodyBytes(cert certDoc) ([]byte, error) {
	body := struct {
		ID        string       `json:"id"`
		Issuer    string       `json:"issuer"`
		PublicKey publicKeyDoc `json:"public_key"`
		Expire    string       `json:"expire"`
	}{
		ID:        cert.ID,
		Issuer:    cert.Issuer,
		PublicKey: cert.PublicKey,
		Expire:    cert.Expire,
	}
	return json.Marshal(body)
}

// rsaSignSHA256PKCS1v15 RSA签名函数接口
func rsaSignSHA256PKCS1v15(message []byte, privateKey rsaPrivateKey) ([]byte, error) {
	hash := sha256.Sum256(message)
	em, err := emsaPKCS1v15Encode(hash[:], rsaBits/8)
	if err != nil {
		return nil, err
	}
	m := new(big.Int).SetBytes(em)
	s := quickPow(m, privateKey.D, privateKey.N)
	return leftPadBytes(s.Bytes(), rsaBits/8), nil
}

// 依照 PKCS#1 v1.5 的 EMSA-PKCS1-v1_5 编码方法实现，适用于 SHA-256 摘要。返回长度为 size 的编码结果。
func emsaPKCS1v15Encode(hash []byte, size int) ([]byte, error) {
	if len(hash) != sha256.Size {
		return nil, errors.New("SHA-256 digest must be 32 bytes")
	}
	tLen := len(sha256DigestInfoPrefix) + len(hash)
	if size < tLen+11 {
		return nil, errors.New("intended encoded message length too short")
	}
	out := make([]byte, size)
	out[0] = 0x00
	out[1] = 0x01
	psLen := size - tLen - 3
	for i := 2; i < 2+psLen; i++ {
		out[i] = 0xff
	}
	out[2+psLen] = 0x00
	copy(out[3+psLen:], sha256DigestInfoPrefix)
	copy(out[3+psLen+len(sha256DigestInfoPrefix):], hash)
	return out, nil
}

// quickPow 对齐 script/rsa_math.h 的快速幂：右移指数、平方取模。
func quickPow(base *big.Int, exp *big.Int, mod *big.Int) *big.Int {
	result := big.NewInt(1)
	baseMod := new(big.Int).Mod(new(big.Int).Set(base), mod)

	e := new(big.Int).Set(exp)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	for e.Cmp(zero) > 0 {
		if new(big.Int).And(e, one).Cmp(one) == 0 {
			result.Mul(result, baseMod)
			result.Mod(result, mod)
		}
		baseMod.Mul(baseMod, baseMod)
		baseMod.Mod(baseMod, mod)
		e.Rsh(e, 1)
	}
	return result
}

// exgcd 用扩展欧几里得求 Bezout 系数。
func exgcd(a *big.Int, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if b.Sign() == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}

	d, x, y := exgcd(b, new(big.Int).Mod(a, b))
	t := new(big.Int).Set(x)
	x = new(big.Int).Set(y)
	y = new(big.Int).Sub(t, new(big.Int).Mul(new(big.Int).Div(a, b), y))
	return d, x, y
}

// 模逆元，返回 a 关于模 m 的逆元，如果不存在则返回 -1。
func modInverse(a *big.Int, m *big.Int) *big.Int {
	g, x, _ := exgcd(new(big.Int).Set(a), new(big.Int).Set(m))
	if g.Cmp(big.NewInt(1)) != 0 {
		return big.NewInt(-1)
	}
	out := new(big.Int).Mod(x, m)
	out.Add(out, m)
	out.Mod(out, m)
	return out
}

// leftPadBytes 将输入字节切片左侧填充零直到达到指定大小，如果输入长度超过大小则截断。
func leftPadBytes(in []byte, size int) []byte {
	out := make([]byte, size)
	if len(in) >= size {
		copy(out, in[len(in)-size:])
		return out
	}
	copy(out[size-len(in):], in)
	return out
}

func hexInt(value *big.Int, width int) string {
	out := fmt.Sprintf("%x", value)
	if width > 0 && len(out) < width {
		out = strings.Repeat("0", width-len(out)) + out
	}
	return out
}

// writeJSON 将 value 以 JSON 格式写入 path，设置权限为 mode。先创建目录，再写入文件，最后设置权限。
func writeJSON(path string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// copyFile 从 src 复制文件到 dst，设置权限为 mode。先读取 src 的内容，再写入 dst。
func copyFile(src string, dst string, mode os.FileMode) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, raw, mode); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
