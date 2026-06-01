package repository

import "strings"

func (s *Store) ensureSchema() error {
	if err := s.dropLegacyAuditRecords(); err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS audit_records (
			id INTEGER PRIMARY KEY,
			ts INTEGER NOT NULL,
			time TEXT NOT NULL,
			kind TEXT NOT NULL,
			event_type TEXT NOT NULL,
			client_id TEXT,
			client_addr TEXT,
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
		`CREATE INDEX IF NOT EXISTS idx_audit_records_pty_session_id ON audit_records(pty_session_id, id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_records_client_target ON audit_records(client_id, target_id, id DESC)`,
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
		`ALTER TABLE ssh_targets ADD COLUMN blocked_clients_json TEXT NOT NULL DEFAULT '[]'`,
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	return nil
}

func (s *Store) dropLegacyAuditRecords() error {
	rows, err := s.db.Query(`PRAGMA table_info(audit_records)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(columns) == 0 {
		return nil
	}
	if columns["session_id"] || columns["client_ip"] || columns["ad_c"] || !columns["client_addr"] {
		_, err := s.db.Exec(`DROP TABLE audit_records`)
		return err
	}
	return nil
}
