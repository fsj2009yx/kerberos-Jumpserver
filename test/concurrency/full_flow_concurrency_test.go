package concurrency_test

import (
	"bytes"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	asconfig "security-project/as_server/config"
	asservice "security-project/as_server/service"
	cryptoutil "security-project/common/crypto"
	"security-project/common/krb"
	tgsconfig "security-project/tgs_server/config"
	tgsservice "security-project/tgs_server/service"
	verifyconfig "security-project/verify_server/config"
	verifyservice "security-project/verify_server/service"
)

const (
	// 并发客户端数需要和临时 AS/V 客户端白名单数量保持一致。
	concurrentClients = 100
	idTGS             = "TGS"
	idV               = "verify_server"

	// V 端 PTY 子协议事件和操作码，测试会覆盖 open/input/close 的最小业务闭环。
	ptyEventOpenOK = 0x11
	ptyEventOutput = 0x12
	ptyEventExit   = 0x13
	ptyOpOpen      = 0x01
	ptyOpInput     = 0x02
	ptyOpClose     = 0x05
)

type testEnv struct {
	asAddr     string
	tgsAddr    string
	vAddr      string
	clientPriv *cryptoutil.RSAKey
	vPub       *cryptoutil.RSAKey
}

func TestConcurrentKerberosFullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skip concurrent end-to-end flow in short mode")
	}

	env := setupConcurrentEnv(t, concurrentClients)

	var wg sync.WaitGroup
	errCh := make(chan error, concurrentClients)
	for i := 0; i < concurrentClients; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			clientID := fmt.Sprintf("CLIENT_%03d", i+1)
			if err := runFullFlowClient(env, clientID, i); err != nil {
				errCh <- fmt.Errorf("%s: %w", clientID, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	var errs []string
	for err := range errCh {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		t.Fatalf("concurrent full flow failed (%d/%d):\n%s", len(errs), concurrentClients, strings.Join(errs, "\n"))
	}
}

func setupConcurrentEnv(t *testing.T, n int) *testEnv {
	t.Helper()

	root := t.TempDir()
	keysDir := filepath.Join(root, "keys")
	certsDir := filepath.Join(root, "certs")
	logsDir := filepath.Join(root, "logs")
	mustMkdirAll(t, keysDir)
	mustMkdirAll(t, certsDir)
	mustMkdirAll(t, logsDir)

	clientStdPriv, err := stdrsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client rsa key: %v", err)
	}
	clientPriv := stdlibPrivToRaw(clientStdPriv)
	clientPub := clientPriv.PublicKey()

	// V 的私钥用于给 APP_REP 签名，测试客户端用对应公钥校验响应不可否认性。
	vStdPriv, err := stdrsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate v rsa key: %v", err)
	}
	vPriv := stdlibPrivToRaw(vStdPriv)
	vPub := vPriv.PublicKey()

	kTGSPath := filepath.Join(keysDir, "k_tgs.bin")
	kVPath := filepath.Join(keysDir, "k_v.bin")
	// k_tgs 由 AS/TGS 共享，k_v 由 TGS/V 共享；这两把 8 字节 DES 密钥把票据链路串起来。
	mustWriteFile(t, kTGSPath, []byte("KTGSKEY!"))
	mustWriteFile(t, kVPath, []byte("KVKEY123"))

	vPrivPath := filepath.Join(keysDir, "v_priv.json")
	writeRSAKeyJSON(t, vPrivPath, vPriv)
	vCertPath := filepath.Join(certsDir, "v_cert.json")
	writeCertificate(t, vCertPath, idV, "TEST_ISSUER", "2035-12-31", vPriv, vPub)

	clientEntriesAS := make([]asconfig.ClientEntry, 0, n)
	clientEntriesV := make([]verifyconfig.ClientCertEntry, 0, n)
	for i := 0; i < n; i++ {
		clientID := fmt.Sprintf("CLIENT_%03d", i+1)
		clientCertPath := filepath.Join(certsDir, strings.ToLower(clientID)+"_cert.json")
		writeCertificate(t, clientCertPath, clientID, "TEST_ISSUER", "2035-12-31", clientPriv, clientPub)
		kc, err := krb.LoadKey8("", "kc:"+clientID)
		if err != nil {
			t.Fatalf("derive kc for %s: %v", clientID, err)
		}
		// AS 需要客户端长期密钥 K_c 来加密 AS_REP；V 需要客户端证书来校验 APP_REQ 签名。
		clientEntriesAS = append(clientEntriesAS, asconfig.ClientEntry{
			ID:       clientID,
			KcHex:    hex.EncodeToString(kc[:]),
			CertPath: clientCertPath,
		})
		clientEntriesV = append(clientEntriesV, verifyconfig.ClientCertEntry{
			ID:       clientID,
			CertPath: clientCertPath,
		})
	}

	asPort := freePort(t)
	asWebPort := freePort(t)
	tgsPort := freePort(t)
	tgsWebPort := freePort(t)
	vPort := freePort(t)
	vWebPort := freePort(t)

	asCfg := asconfig.Config{
		NodeID:     "AS",
		ListenHost: "127.0.0.1",
		ListenPort: asPort,
		WebUIHost:  "127.0.0.1",
		WebUIPort:  asWebPort,
		// AS 配置校验要求线程池大小大于 0；当前服务实现实际按连接启动 goroutine。
		ThreadPoolSize: 8,
		// 重放窗口必须大于并发请求规模，避免同一秒内不同客户端请求被窗口容量挤出。
		AntiReplayWindow: 4096,
		// 票据有效期覆盖整个测试运行时间，使失败更集中暴露在并发和协议处理上。
		TicketLifetimeSec: 600,
		// MaxClients 与测试并发客户端数一致，确保所有临时客户端都能通过 AS 配置校验。
		MaxClients: n,
		// 64 KiB 覆盖 AS_REP/TGS_REP/APP 帧，和测试客户端读取上限保持一致。
		MaxPayloadBytes: 64 * 1024,
		// 超时时间给并发建连和 PTY 回显留余量，同时避免失败时无限阻塞。
		ReadTimeoutSec:  15,
		CertPath:        "",
		PrivKeyPath:     "",
		LogLevel:        "INFO",
		LogFile:         filepath.Join(logsDir, "as.log"),
		SecurityLogFile: filepath.Join(logsDir, "as_security.log"),
		// AS 用 k_tgs 加密 TGT；TGS 必须加载同一文件才能解密票据。
		KtgsPath: kTGSPath,
		// AS 客户端库提供每个 CLIENT_xxx 的 K_c 和证书路径，是并发身份注册的基础。
		ClientDB: clientEntriesAS,
	}
	tgsCfg := tgsconfig.Config{
		NodeID:           idTGS,
		ListenHost:       "127.0.0.1",
		ListenPort:       tgsPort,
		WebUIHost:        "127.0.0.1",
		WebUIPort:        tgsWebPort,
		AntiReplayWindow: 4096,
		// TGS 生成给 V 的服务票据，生命周期需覆盖后续 AP 和 APP 阶段。
		TicketLifetimeSec: 600,
		MaxPayloadBytes:   64 * 1024,
		ReadTimeoutSec:    15,
		CertPath:          "",
		PrivKeyPath:       "",
		LogLevel:          "INFO",
		LogFile:           filepath.Join(logsDir, "tgs.log"),
		SecurityLogFile:   filepath.Join(logsDir, "tgs_security.log"),
		// 与 AS 使用同一 k_tgs，验证 AS 发出的 TGT 可以被 TGS 解密。
		KTGSPath: kTGSPath,
		// ServiceDB 把 id_v 映射到 k_v；客户端请求 idV 时会拿到可被 V 解密的 Ticket_V。
		ServiceDB: []tgsconfig.ServiceEntry{
			{IDV: idV, KVPath: kVPath, Addr: fmt.Sprintf("127.0.0.1:%d", vPort)},
		},
	}
	vCfg := verifyconfig.Config{
		NodeID:           idV,
		ListenHost:       "127.0.0.1",
		ListenPort:       vPort,
		WebUIHost:        "127.0.0.1",
		WebUIPort:        vWebPort,
		AntiReplayWindow: 4096,
		MaxPayloadBytes:  64 * 1024,
		// V 阶段包含 AP 认证、PTY open/input/close 和异步输出读取，超时略大于 AS/TGS。
		ReadTimeoutSec: 30,
		// V 证书/私钥用于 APP_REP 签名，测试客户端用 vPub 验签。
		CertPath:        vCertPath,
		PrivKeyPath:     vPrivPath,
		LogLevel:        "INFO",
		LogFile:         filepath.Join(logsDir, "v.log"),
		SecurityLogFile: filepath.Join(logsDir, "v_security.log"),
		// 与 TGS ServiceDB 中的 k_v 保持一致，验证 Ticket_V 可以被 V 解密。
		KVPath: kVPath,
		// 使用真实 shell 打开 PTY，会执行 printf marker 并等待输出回显。
		PTYShell:       "/bin/sh",
		PTYDefaultTerm: "xterm-256color",
		// V 客户端库用于 APP_REQ RSA 验签；数量需要覆盖所有并发客户端。
		ClientDB: clientEntriesV,
	}

	asCfgPath := filepath.Join(root, "as_config.json")
	tgsCfgPath := filepath.Join(root, "tgs_config.json")
	vCfgPath := filepath.Join(root, "v_config.json")
	writeJSON(t, asCfgPath, asCfg)
	writeJSON(t, tgsCfgPath, tgsCfg)
	writeJSON(t, vCfgPath, vCfg)

	go func() {
		if err := asservice.NewService(asCfgPath).Run(); err != nil {
			panic(fmt.Sprintf("as service exited: %v", err))
		}
	}()
	go func() {
		if err := tgsservice.NewService(tgsCfgPath).Run(); err != nil {
			panic(fmt.Sprintf("tgs service exited: %v", err))
		}
	}()
	go func() {
		if err := verifyservice.NewService(vCfgPath).Run(); err != nil {
			panic(fmt.Sprintf("verify service exited: %v", err))
		}
	}()

	asAddr := fmt.Sprintf("127.0.0.1:%d", asPort)
	tgsAddr := fmt.Sprintf("127.0.0.1:%d", tgsPort)
	vAddr := fmt.Sprintf("127.0.0.1:%d", vPort)
	waitForTCP(t, asAddr)
	waitForTCP(t, tgsAddr)
	waitForTCP(t, vAddr)

	return &testEnv{
		asAddr:     asAddr,
		tgsAddr:    tgsAddr,
		vAddr:      vAddr,
		clientPriv: clientPriv,
		vPub:       vPub,
	}
}

func runFullFlowClient(env *testEnv, clientID string, idx int) error {
	kc, err := krb.LoadKey8("", "kc:"+clientID)
	if err != nil {
		return fmt.Errorf("derive kc: %w", err)
	}
	adc := krb.ToUint32IP(net.ParseIP("127.0.0.1"))

	keyCTGS, ticketTGS, err := doAS(env.asAddr, clientID, kc)
	if err != nil {
		return fmt.Errorf("as flow: %w", err)
	}
	keyCV, ticketV, err := doTGS(env.tgsAddr, clientID, adc, keyCTGS, ticketTGS)
	if err != nil {
		return fmt.Errorf("tgs flow: %w", err)
	}
	if err := doV(env.vAddr, clientID, adc, keyCV, ticketV, env.clientPriv, env.vPub, idx); err != nil {
		return fmt.Errorf("v flow: %w", err)
	}
	return nil
}

func doAS(addr, clientID string, kc [8]byte) ([8]byte, []byte, error) {
	var zero [8]byte
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return zero, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	ts1 := uint32(time.Now().Unix())
	reqPayload := buildASReqPayload(clientID, idTGS, ts1)
	if err := krb.WritePacket(conn, krb.MsgASReq, 1, ts1, reqPayload); err != nil {
		return zero, nil, err
	}
	h, payload, err := krb.ReadPacket(conn, 64*1024)
	if err != nil {
		return zero, nil, err
	}
	if h.MsgType == krb.MsgErr {
		return zero, nil, decodeErrorPayload(payload)
	}
	if h.MsgType != krb.MsgASRep {
		return zero, nil, fmt.Errorf("unexpected AS response type: %d", h.MsgType)
	}
	wire, err := krb.ParseASRepPayload(payload)
	if err != nil {
		return zero, nil, err
	}
	plain, err := cryptoutil.DecryptDESCBC(kc, wire.EncPart)
	if err != nil {
		return zero, nil, err
	}
	keyCTGS, gotIDTGS, _, _, ticketTGS, err := decodeASRepPlain(plain)
	if err != nil {
		return zero, nil, err
	}
	if gotIDTGS != idTGS {
		return zero, nil, fmt.Errorf("unexpected id_tgs: %s", gotIDTGS)
	}
	return keyCTGS, ticketTGS, nil
}

func doTGS(addr, clientID string, adc uint32, keyCTGS [8]byte, ticketTGS []byte) ([8]byte, []byte, error) {
	var zero [8]byte
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return zero, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	ts3 := uint32(time.Now().Unix())
	authCipher, err := buildAuthenticatorCTGSCipher(keyCTGS, clientID, adc, ts3)
	if err != nil {
		return zero, nil, err
	}
	reqPayload := buildTGSReqPayload(idV, ticketTGS, authCipher)
	if err := krb.WritePacket(conn, krb.MsgTGSReq, 1, ts3, reqPayload); err != nil {
		return zero, nil, err
	}
	h, payload, err := krb.ReadPacket(conn, 64*1024)
	if err != nil {
		return zero, nil, err
	}
	if h.MsgType == krb.MsgErr {
		return zero, nil, decodeErrorPayload(payload)
	}
	if h.MsgType != krb.MsgTGSRep {
		return zero, nil, fmt.Errorf("unexpected TGS response type: %d", h.MsgType)
	}
	wire, err := krb.ParseASRepPayload(payload)
	if err != nil {
		return zero, nil, err
	}
	plain, err := cryptoutil.DecryptDESCBC(keyCTGS, wire.EncPart)
	if err != nil {
		return zero, nil, err
	}
	keyCV, gotIDV, _, _, ticketV, err := decodeTGSRepPlain(plain)
	if err != nil {
		return zero, nil, err
	}
	if gotIDV != idV {
		return zero, nil, fmt.Errorf("unexpected id_v: %s", gotIDV)
	}
	return keyCV, ticketV, nil
}

func doV(addr, clientID string, adc uint32, keyCV [8]byte, ticketV []byte, clientPriv, vPub *cryptoutil.RSAKey, idx int) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	vSeq := uint32(1)
	ts5 := uint32(time.Now().Unix())
	authCipher, err := buildAuthenticatorCVCipher(keyCV, clientID, adc, ts5)
	if err != nil {
		return err
	}
	apPayload := buildAPReqPayload(ticketV, authCipher)
	if err := krb.WritePacket(conn, krb.MsgAPReq, vSeq, ts5, apPayload); err != nil {
		return err
	}
	h, payload, err := krb.ReadPacket(conn, 64*1024)
	if err != nil {
		return err
	}
	if h.MsgType == krb.MsgErr {
		return decodeErrorPayload(payload)
	}
	if h.MsgType != krb.MsgAPRep {
		return fmt.Errorf("unexpected AP response type: %d", h.MsgType)
	}
	apWire, err := krb.ParseASRepPayload(payload)
	if err != nil {
		return err
	}
	apPlain, err := krb.DecryptAPRepPlain(apWire.EncPart, keyCV)
	if err != nil {
		return err
	}
	if apPlain.TS5Plus1 != ts5+1 {
		return fmt.Errorf("ap ts mismatch: got %d want %d", apPlain.TS5Plus1, ts5+1)
	}

	vSeq++
	openPayload := buildOpenPayload("xterm-256color", 80, 24)
	appOpen, err := buildAPPReqPayload(clientID, vSeq, keyCV, ptyOpOpen, 0, openPayload, clientPriv)
	if err != nil {
		return err
	}
	if err := krb.WritePacket(conn, krb.MsgApp, vSeq, uint32(time.Now().Unix()), appOpen); err != nil {
		return err
	}
	var sessionID uint32
	openDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(openDeadline) {
		frame, err := readAPPFrame(conn, keyCV, vPub)
		if err != nil {
			return fmt.Errorf("await open_ok: %w", err)
		}
		if frame.PtyEvent == ptyEventOpenOK {
			sessionID = frame.PtySessionID
			break
		}
		if frame.PtyEvent == ptyEventExit {
			return fmt.Errorf("got exit before open_ok")
		}
	}
	if sessionID == 0 {
		return errors.New("missing open_ok session id")
	}

	vSeq++
	marker := fmt.Sprintf("marker-%03d", idx)
	inputPayload := []byte(fmt.Sprintf("printf '%s\\n'\n", marker))
	appInput, err := buildAPPReqPayload(clientID, vSeq, keyCV, ptyOpInput, sessionID, inputPayload, clientPriv)
	if err != nil {
		return err
	}
	if err := krb.WritePacket(conn, krb.MsgApp, vSeq, uint32(time.Now().Unix()), appInput); err != nil {
		return err
	}
	var outputBuf bytes.Buffer
	inputDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(inputDeadline) {
		frame, err := readAPPFrame(conn, keyCV, vPub)
		if err != nil {
			return fmt.Errorf("await marker output: %w", err)
		}
		switch frame.PtyEvent {
		case ptyEventOutput:
			outputBuf.Write(frame.Payload)
			if strings.Contains(outputBuf.String(), marker) {
				goto closeSession
			}
		case ptyEventExit:
			return fmt.Errorf("got exit before marker output")
		}
	}
	return fmt.Errorf("marker %q not observed, output=%q", marker, outputBuf.String())

closeSession:
	vSeq++
	appClose, err := buildAPPReqPayload(clientID, vSeq, keyCV, ptyOpClose, sessionID, nil, clientPriv)
	if err != nil {
		return err
	}
	if err := krb.WritePacket(conn, krb.MsgApp, vSeq, uint32(time.Now().Unix()), appClose); err != nil {
		return err
	}
	closeDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(closeDeadline) {
		frame, err := readAPPFrame(conn, keyCV, vPub)
		if err != nil {
			return fmt.Errorf("await exit: %w", err)
		}
		if frame.PtyEvent == ptyEventExit {
			return nil
		}
	}
	return errors.New("missing close exit event")
}

func readAPPFrame(conn net.Conn, keyCV [8]byte, vPub *cryptoutil.RSAKey) (krb.APPRepPlain, error) {
	h, payload, err := krb.ReadPacket(conn, 64*1024)
	if err != nil {
		return krb.APPRepPlain{}, err
	}
	if h.MsgType == krb.MsgErr {
		return krb.APPRepPlain{}, decodeErrorPayload(payload)
	}
	if h.MsgType != krb.MsgApp {
		return krb.APPRepPlain{}, fmt.Errorf("unexpected msg type: %d", h.MsgType)
	}
	wire, err := krb.ParseAPPRepPayload(payload)
	if err != nil {
		return krb.APPRepPlain{}, err
	}
	if err := krb.VerifyCipherSignature(h.SeqNum, wire.Cipher, wire.RSASignV, vPub); err != nil {
		return krb.APPRepPlain{}, err
	}
	return krb.DecryptAPPRepPlain(wire.Cipher, keyCV)
}

func buildASReqPayload(idClient, gotIDTGS string, ts1 uint32) []byte {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(idClient))
	raw.Write(krb.EncodeKString(gotIDTGS))
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], ts1)
	raw.Write(tmp[:])
	return raw.Bytes()
}

func buildTGSReqPayload(gotIDV string, ticketCipher, authCipher []byte) []byte {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(gotIDV))
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(ticketCipher)))
	raw.Write(tmp4[:])
	raw.Write(ticketCipher)
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(authCipher)))
	raw.Write(tmp4[:])
	raw.Write(authCipher)
	return raw.Bytes()
}

func buildAPReqPayload(ticketCipher, authCipher []byte) []byte {
	raw := bytes.NewBuffer(nil)
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(ticketCipher)))
	raw.Write(tmp4[:])
	raw.Write(ticketCipher)
	binary.BigEndian.PutUint32(tmp4[:], uint32(len(authCipher)))
	raw.Write(tmp4[:])
	raw.Write(authCipher)
	return raw.Bytes()
}

func buildAuthenticatorCTGSCipher(key [8]byte, client string, adc, ts3 uint32) ([]byte, error) {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(client))
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], adc)
	raw.Write(tmp4[:])
	binary.BigEndian.PutUint32(tmp4[:], ts3)
	raw.Write(tmp4[:])
	return cryptoutil.EncryptDESCBC(key, raw.Bytes())
}

func buildAuthenticatorCVCipher(key [8]byte, client string, adc, ts5 uint32) ([]byte, error) {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(client))
	var tmp4 [4]byte
	binary.BigEndian.PutUint32(tmp4[:], adc)
	raw.Write(tmp4[:])
	binary.BigEndian.PutUint32(tmp4[:], ts5)
	raw.Write(tmp4[:])
	return cryptoutil.EncryptDESCBC(key, raw.Bytes())
}

func buildAPPReqPayload(clientID string, seq uint32, keyCV [8]byte, ptyOp uint8, ptySessionID uint32, payload []byte, clientPriv *cryptoutil.RSAKey) ([]byte, error) {
	body := bytes.NewBuffer(nil)
	body.WriteByte(ptyOp)
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp4, ptySessionID)
	body.Write(tmp4)
	binary.BigEndian.PutUint32(tmp4, uint32(len(payload)))
	body.Write(tmp4)
	body.Write(payload)
	cipherData, err := cryptoutil.EncryptDESCBC(keyCV, body.Bytes())
	if err != nil {
		return nil, err
	}
	rawToSign := make([]byte, 4+len(cipherData))
	binary.BigEndian.PutUint32(rawToSign[:4], seq)
	copy(rawToSign[4:], cipherData)
	sig, err := krb.SignSHA256(rawToSign, clientPriv)
	if err != nil {
		return nil, err
	}
	wire := bytes.NewBuffer(nil)
	wire.Write(krb.EncodeKString(clientID))
	tmp2 := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp2, uint16(len(cipherData)))
	wire.Write(tmp2)
	wire.Write(cipherData)
	wire.Write(sig[:])
	return wire.Bytes(), nil
}

func buildOpenPayload(term string, cols, rows uint16) []byte {
	raw := bytes.NewBuffer(nil)
	raw.Write(krb.EncodeKString(term))
	var tmp2 [2]byte
	binary.BigEndian.PutUint16(tmp2[:], cols)
	raw.Write(tmp2[:])
	binary.BigEndian.PutUint16(tmp2[:], rows)
	raw.Write(tmp2[:])
	return raw.Bytes()
}

func decodeASRepPlain(raw []byte) ([8]byte, string, uint32, uint32, []byte, error) {
	var key [8]byte
	if len(raw) < 8 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	copy(key[:], raw[:8])
	idTGSData, off, err := krb.DecodeKString(raw[8:])
	if err != nil {
		return key, "", 0, 0, nil, err
	}
	if len(raw) < 8+off+12 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	base := 8 + off
	ts2 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	ticketLen := binary.BigEndian.Uint32(raw[base+8 : base+12])
	if len(raw) < base+12+int(ticketLen) {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return key, string(idTGSData.Data), ts2, lifetime, append([]byte(nil), raw[base+12:base+12+int(ticketLen)]...), nil
}

func decodeTGSRepPlain(raw []byte) ([8]byte, string, uint32, uint32, []byte, error) {
	var key [8]byte
	if len(raw) < 8 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	copy(key[:], raw[:8])
	idVData, off, err := krb.DecodeKString(raw[8:])
	if err != nil {
		return key, "", 0, 0, nil, err
	}
	base := 8 + off
	if len(raw) < base+12 {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	ts4 := binary.BigEndian.Uint32(raw[base : base+4])
	lifetime := binary.BigEndian.Uint32(raw[base+4 : base+8])
	ticketLen := binary.BigEndian.Uint32(raw[base+8 : base+12])
	if len(raw) < base+12+int(ticketLen) {
		return key, "", 0, 0, nil, krb.ErrorFromCode(krb.ErrTicketInvalid)
	}
	return key, string(idVData.Data), ts4, lifetime, append([]byte(nil), raw[base+12:base+12+int(ticketLen)]...), nil
}

func decodeErrorPayload(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("short error payload")
	}
	return fmt.Errorf("krb error code %d", int32(binary.BigEndian.Uint32(payload[:4])))
}

func writeCertificate(t *testing.T, path, id, issuer, expire string, signerPriv, pub *cryptoutil.RSAKey) {
	t.Helper()
	cert := &krb.Certificate{
		ID:     id,
		Issuer: issuer,
		Expire: expire,
	}
	cert.PublicKey.N = fmt.Sprintf("%x", pub.N)
	cert.PublicKey.E = fmt.Sprintf("%x", pub.E)
	body, err := krb.CertBodyBytes(cert)
	if err != nil {
		t.Fatalf("build cert body: %v", err)
	}
	sig, err := krb.SignSHA256(body, signerPriv)
	if err != nil {
		t.Fatalf("sign cert body: %v", err)
	}
	cert.Sign = hex.EncodeToString(sig[:])
	writeJSON(t, path, cert)
}

func writeRSAKeyJSON(t *testing.T, path string, key *cryptoutil.RSAKey) {
	t.Helper()
	doc := krb.RSAKeyJSON{
		N: fmt.Sprintf("%x", key.N),
		E: fmt.Sprintf("%x", key.E),
		D: fmt.Sprintf("%x", key.D),
	}
	writeJSON(t, path, doc)
}

func stdlibPrivToRaw(priv *stdrsa.PrivateKey) *cryptoutil.RSAKey {
	return &cryptoutil.RSAKey{
		N: new(big.Int).Set(priv.N),
		E: big.NewInt(int64(priv.E)),
		D: new(big.Int).Set(priv.D),
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal json %s: %v", path, err)
	}
	mustWriteFile(t, path, b)
}

func mustWriteFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("service %s not ready before deadline", addr)
}
