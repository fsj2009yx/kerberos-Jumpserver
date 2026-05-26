package repository

import "strings"

func (s *Store) ensureSchema() error {
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
			target_id TEXT,
			target_host TEXT,
			ssh_user TEXT,
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
		`CREATE TABLE IF NOT EXISTS ssh_targets (
			id TEXT PRIMARY KEY,
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			ssh_user TEXT NOT NULL,
			auth_type TEXT NOT NULL,
			key_path TEXT,
			password_cipher TEXT,
			password_hash TEXT,
			known_hosts_path TEXT,
			blocked_clients_json TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ssh_targets_updated_at ON ssh_targets(updated_at DESC)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	for _, stmt := range []string{
		`ALTER TABLE audit_records ADD COLUMN target_id TEXT`,
		`ALTER TABLE audit_records ADD COLUMN target_host TEXT`,
		`ALTER TABLE audit_records ADD COLUMN ssh_user TEXT`,
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	return nil
}
