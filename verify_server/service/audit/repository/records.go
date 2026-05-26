package repository

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"security-project/common/krb"
	"security-project/verify_server/service/audit/model"
)

func (s *Store) initTail() error {
	var last model.Record
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

func (s *Store) Append(rec model.Record) error {
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
	rec.RecordHash = recordHash(rec)

	_, err := s.db.Exec(`INSERT INTO audit_records (
		id, ts, time, kind, event_type, session_id, client_id, client_ip, ad_c, target_id, target_host, ssh_user, pty_session_id,
		direction, seq_num, msg_type, pty_op, pty_event, frame_type, frame_size, payload_b64,
		exit_code, result, error_code, rsa_verify_result, prev_hash, record_hash
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.TS, rec.Time, rec.Kind, rec.EventType, rec.SessionID, rec.ClientID, rec.ClientIP, rec.ADc, rec.TargetID, rec.TargetHost, rec.SSHUser, rec.PTYSessionID,
		rec.Direction, rec.SeqNum, rec.MsgType, rec.PTYOp, rec.PTYEvent, rec.FrameType, rec.FrameSize, rec.PayloadB64,
		rec.ExitCode, rec.Result, rec.ErrorCode, rec.RSAVerifyResult, rec.PrevHash, rec.RecordHash)
	if err != nil {
		return err
	}
	s.nextID++
	s.lastHash = rec.RecordHash
	return nil
}

func (s *Store) Records(limit int, filter func(model.Record) bool) ([]model.Record, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT
		id, ts, time, kind, event_type, session_id, client_id, client_ip, ad_c, target_id, target_host, ssh_user, pty_session_id,
		direction, seq_num, msg_type, pty_op, pty_event, frame_type, frame_size, payload_b64,
		exit_code, result, error_code, rsa_verify_result, prev_hash, record_hash
		FROM audit_records
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]model.Record, 0, limit)
	for rows.Next() {
		rec, err := scanRecord(rows)
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

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(row scanner) (model.Record, error) {
	var rec model.Record
	var sessionID, clientID, clientIP, targetID, targetHost, sshUser, direction, frameType, payloadB64, errorCode, rsaVerifyResult, prevHash sql.NullString
	var adC, ptySessionID, seqNum, msgType, ptyOp, ptyEvent, frameSize, exitCode sql.NullInt64
	err := row.Scan(
		&rec.ID, &rec.TS, &rec.Time, &rec.Kind, &rec.EventType, &sessionID, &clientID, &clientIP, &adC, &targetID, &targetHost, &sshUser, &ptySessionID,
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
	rec.TargetID = nullString(targetID)
	rec.TargetHost = nullString(targetHost)
	rec.SSHUser = nullString(sshUser)
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

func recordHash(rec model.Record) string {
	rec.RecordHash = ""
	raw, _ := json.Marshal(rec)
	input := append([]byte(rec.PrevHash), raw...)
	sum := krb.Hash256(input)
	return hex.EncodeToString(sum[:])
}
