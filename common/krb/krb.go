//kerberos中使用的一些工具函数和数据结构，例如重放窗口、密钥加载、IP地址转换等。

package krb

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"security-project/common/crypto"
	"security-project/common/krb/protocol"
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

// LoadKey8 (测试用）
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

// EnsureDir 确保指定路径存在，如果路径不存在则创建它，权限为755。
func EnsureDir(path string) error {
	if path == "" {
		return nil
	}
	return os.MkdirAll(path, 0o755)
}
