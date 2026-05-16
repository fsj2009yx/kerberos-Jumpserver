package service

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"security-project/common/krb"
	"security-project/pkg/utils/log"

	_ "github.com/mattn/go-sqlite3"
)

const defaultAuditDBFile = "logs/v_audit.db"

type AuditRecord struct {
	ID              uint64 `json:"id"`
	TS              int64  `json:"ts"`
	Time            string `json:"time"`
	Kind            string `json:"kind"`
	EventType       string `json:"event_type"`
	SessionID       string `json:"session_id"`
	ClientID        string `json:"client_id,omitempty"`
	ClientIP        string `json:"client_ip,omitempty"`
	ADc             uint32 `json:"ad_c,omitempty"`
	PTYSessionID    uint32 `json:"pty_session_id,omitempty"`
	Direction       string `json:"direction,omitempty"`
	SeqNum          uint32 `json:"seq_num,omitempty"`
	MsgType         uint8  `json:"msg_type,omitempty"`
	PTYOp           uint8  `json:"pty_op,omitempty"`
	PTYEvent        uint8  `json:"pty_event,omitempty"`
	FrameType       string `json:"frame_type,omitempty"`
	FrameSize       int    `json:"frame_size,omitempty"`
	PayloadB64      string `json:"payload_b64,omitempty"`
	ExitCode        int32  `json:"exit_code,omitempty"`
	Result          string `json:"result"`
	ErrorCode       string `json:"error_code,omitempty"`
	RSAVerifyResult string `json:"rsa_verify_result,omitempty"`
	PrevHash        string `json:"prev_hash,omitempty"`
	RecordHash      string `json:"record_hash"`
}

type AuditStore struct {
	path     string
	db       *sql.DB
	mu       sync.Mutex
	nextID   uint64
	lastHash string
}

func NewAuditStore(path string) (*AuditStore, error) {
	if strings.TrimSpace(path) == "" {
		path = defaultAuditDBFile
	}
	if !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", sqliteAuditDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &AuditStore{path: path, db: db, nextID: 1}
	if err := store.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.initTail(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if !strings.HasPrefix(path, "file:") {
		_ = os.Chmod(path, 0o600)
	}
	return store, nil
}

func sqliteAuditDSN(path string) string {
	if strings.HasPrefix(path, "file:") {
		return path
	}
	return fmt.Sprintf("file:%s?cache=shared&mode=rwc&_busy_timeout=5000&_journal_mode=WAL", filepath.ToSlash(path))
}

func (s *AuditStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *AuditStore) ensureSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS audit_records (
			id INTEGER PRIMARY KEY,
			ts INTEGER NOT NULL,
			time TEXT NOT NULL,
			kind TEXT NOT NULL,
			event_type TEXT NOT NULL,
			session_id TEXT,
			client_id TEXT,
			client_ip TEXT,
			ad_c INTEGER,
			pty_session_id INTEGER,
			direction TEXT,
			seq_num INTEGER,
			msg_type INTEGER,
			pty_op INTEGER,
			pty_event INTEGER,
			frame_type TEXT,
			frame_size INTEGER,
			payload_b64 TEXT,
			exit_code INTEGER,
			result TEXT NOT NULL,
			error_code TEXT,
			rsa_verify_result TEXT,
			prev_hash TEXT,
			record_hash TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_records_kind_id ON audit_records(kind, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_records_session_id ON audit_records(session_id, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_records_pty_session_id ON audit_records(pty_session_id, id DESC)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *AuditStore) initTail() error {
	var last AuditRecord
	row := s.db.QueryRow(`SELECT id, record_hash FROM audit_records ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&last.ID, &last.RecordHash); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	s.nextID = last.ID + 1
	s.lastHash = last.RecordHash
	return nil
}

func (s *AuditStore) Append(rec AuditRecord) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	rec.ID = s.nextID
	rec.TS = now.Unix()
	rec.Time = now.Format(time.RFC3339Nano)
	rec.PrevHash = s.lastHash
	rec.RecordHash = auditRecordHash(rec)

	_, err := s.db.Exec(`INSERT INTO audit_records (
		id, ts, time, kind, event_type, session_id, client_id, client_ip, ad_c, pty_session_id,
		direction, seq_num, msg_type, pty_op, pty_event, frame_type, frame_size, payload_b64,
		exit_code, result, error_code, rsa_verify_result, prev_hash, record_hash
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.TS, rec.Time, rec.Kind, rec.EventType, rec.SessionID, rec.ClientID, rec.ClientIP, rec.ADc, rec.PTYSessionID,
		rec.Direction, rec.SeqNum, rec.MsgType, rec.PTYOp, rec.PTYEvent, rec.FrameType, rec.FrameSize, rec.PayloadB64,
		rec.ExitCode, rec.Result, rec.ErrorCode, rec.RSAVerifyResult, rec.PrevHash, rec.RecordHash)
	if err != nil {
		return err
	}
	s.nextID++
	s.lastHash = rec.RecordHash
	return nil
}

func (s *AuditStore) Records(limit int, filter func(AuditRecord) bool) ([]AuditRecord, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT
		id, ts, time, kind, event_type, session_id, client_id, client_ip, ad_c, pty_session_id,
		direction, seq_num, msg_type, pty_op, pty_event, frame_type, frame_size, payload_b64,
		exit_code, result, error_code, rsa_verify_result, prev_hash, record_hash
		FROM audit_records
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]AuditRecord, 0, limit)
	for rows.Next() {
		rec, err := scanAuditRecord(rows)
		if err != nil {
			return nil, err
		}
		if filter == nil || filter(rec) {
			records = append(records, rec)
			if len(records) >= limit {
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

type auditScanner interface {
	Scan(dest ...any) error
}

func scanAuditRecord(row auditScanner) (AuditRecord, error) {
	var rec AuditRecord
	var sessionID, clientID, clientIP, direction, frameType, payloadB64, errorCode, rsaVerifyResult, prevHash sql.NullString
	var adC, ptySessionID, seqNum, msgType, ptyOp, ptyEvent, frameSize, exitCode sql.NullInt64
	err := row.Scan(
		&rec.ID, &rec.TS, &rec.Time, &rec.Kind, &rec.EventType, &sessionID, &clientID, &clientIP, &adC, &ptySessionID,
		&direction, &seqNum, &msgType, &ptyOp, &ptyEvent, &frameType, &frameSize, &payloadB64,
		&exitCode, &rec.Result, &errorCode, &rsaVerifyResult, &prevHash, &rec.RecordHash,
	)
	if err != nil {
		return rec, err
	}
	rec.SessionID = nullString(sessionID)
	rec.ClientID = nullString(clientID)
	rec.ClientIP = nullString(clientIP)
	rec.ADc = uint32(nullInt(adC))
	rec.PTYSessionID = uint32(nullInt(ptySessionID))
	rec.Direction = nullString(direction)
	rec.SeqNum = uint32(nullInt(seqNum))
	rec.MsgType = uint8(nullInt(msgType))
	rec.PTYOp = uint8(nullInt(ptyOp))
	rec.PTYEvent = uint8(nullInt(ptyEvent))
	rec.FrameType = nullString(frameType)
	rec.FrameSize = int(nullInt(frameSize))
	rec.PayloadB64 = nullString(payloadB64)
	rec.ExitCode = int32(nullInt(exitCode))
	rec.ErrorCode = nullString(errorCode)
	rec.RSAVerifyResult = nullString(rsaVerifyResult)
	rec.PrevHash = nullString(prevHash)
	return rec, nil
}

func nullString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullInt(value sql.NullInt64) int64 {
	if !value.Valid {
		return 0
	}
	return value.Int64
}

func auditRecordHash(rec AuditRecord) string {
	rec.RecordHash = ""
	raw, _ := json.Marshal(rec)
	input := append([]byte(rec.PrevHash), raw...)
	sum := krb.Hash256(input)
	return hex.EncodeToString(sum[:])
}

func auditPayload(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func auditSessionID(clientID string, ptySessionID uint32) string {
	if ptySessionID == 0 {
		return clientID
	}
	return fmt.Sprintf("%s:%d", clientID, ptySessionID)
}

func auditPTYOpName(op uint8) string {
	switch op {
	case 0x01:
		return "open"
	case 0x02:
		return "input"
	case 0x03:
		return "resize"
	case 0x04:
		return "signal"
	case 0x05:
		return "close"
	default:
		return fmt.Sprintf("op_%d", op)
	}
}

func auditPTYEventName(event uint8) string {
	switch event {
	case 0x11:
		return "open_ok"
	case 0x12:
		return "output"
	case 0x13:
		return "exit"
	case 0x14:
		return "error"
	default:
		return fmt.Sprintf("event_%d", event)
	}
}

func auditLimit(rLimit string) int {
	limit, err := strconv.Atoi(rLimit)
	if err != nil {
		return 100
	}
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func (s *Service) appendAudit(rec AuditRecord) {
	if s == nil || s.audit == nil {
		return
	}
	if err := s.audit.Append(rec); err != nil {
		log.Warnf("[V] audit append failed kind=%s event=%s client=%s err=%v", rec.Kind, rec.EventType, rec.ClientID, err)
	}
}
