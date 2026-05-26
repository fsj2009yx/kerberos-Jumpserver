package krb

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"security-project/common/crypto"
	"security-project/common/krb/protocol"
	"strings"
	"sync"
	"time"
)

type ReplayWindow struct {
	mu     sync.Mutex
	scopes map[string]*replayScope
	max    int
}

type replayScope struct {
	seen  map[uint32]struct{}
	order []uint32
}

func NewReplayWindow(max int) *ReplayWindow {
	if max <= 0 {
		max = 1024
	}
	return &ReplayWindow{scopes: make(map[string]*replayScope), max: max}
}

func (r *ReplayWindow) Check(ts, seq uint32) error {
	return r.CheckScoped("", ts, seq)
}

// CheckScoped 检查给定的时间戳和序列号是否在重放窗口内，并且在指定的作用域内没有被重复使用过。
func (r *ReplayWindow) CheckScoped(scope string, ts, seq uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := uint32(time.Now().Unix())
	diff := int64(ts) - int64(now)
	if diff < 0 {
		diff = -diff
	}
	// 如果时间戳与当前时间的差值超过5秒，则认为是重放攻击，返回相应的错误码。
	if diff > 5 {
		return protocol.ErrorFromCode(protocol.ErrReplayTimestamp)
	}

	rs, ok := r.scopes[scope]
	if !ok {
		rs = &replayScope{
			seen:  make(map[uint32]struct{}, r.max),
			order: make([]uint32, 0, r.max),
		}
		r.scopes[scope] = rs
	}
	if _, ok := rs.seen[seq]; ok {
		return protocol.ErrorFromCode(protocol.ErrReplaySeq)
	}
	rs.seen[seq] = struct{}{}
	rs.order = append(rs.order, seq)
	if len(rs.order) > r.max {
		old := rs.order[0]
		rs.order = rs.order[1:]
		delete(rs.seen, old)
	}
	return nil
}

// LoadKey8 从指定路径加载一个8字节的密钥（DES密钥），
// 如果路径为空或加载失败，则使用fallbackSeed生成一个8字节的密钥。返回加载的密钥和错误信息。
func LoadKey8(path string, fallbackSeed string) ([8]byte, error) {
	var out [8]byte
	if path != "" {
		b, err := os.ReadFile(path)
		if err == nil {
			switch {
			case len(b) == 8:
				copy(out[:], b)
				return out, nil
			default:
				if key, ok := crypto.ParseKeyBytes(b); ok {
					copy(out[:], key)
					return out, nil
				}
			}
		}
	}
	if fallbackSeed == "" {
		return out, errors.New("no key material")
	}
	sum := crypto.Sum256([]byte(fallbackSeed))
	copy(out[:], sum[:8])
	return out, nil
}

func Hash256(data []byte) [32]byte {
	return crypto.Sum256(data)
}

func Uint32ToBytes(v uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, v)
	return out
}

func BytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func BuildSessionKey(seed string) ([8]byte, int32) {
	var out [8]byte
	sum := crypto.Sum256([]byte(seed + time.Now().UTC().Format(time.RFC3339Nano)))
	copy(out[:], sum[:8])
	return out, KRBOK
}

func ToUint32IP(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func PeerIP(conn net.Conn) uint32 {
	if conn == nil {
		return 0
	}
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return ToUint32IP(addr.IP)
}

func EnsureDir(path string) error {
	if path == "" {
		return nil
	}
	return os.MkdirAll(path, 0o755)
}

func WriteJSONFile(path string, v any) error {
	if err := EnsureDir(dirOf(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func dirOf(path string) string {
	if path == "" {
		return ""
	}
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[:i]
	}
	return ""
}

func ContextWithCancel(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithCancel(parent)
}
