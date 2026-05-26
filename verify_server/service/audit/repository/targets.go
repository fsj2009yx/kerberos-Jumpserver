package repository

import (
	"database/sql"
	"fmt"
	"strings"

	"security-project/verify_server/service/audit/model"
)

func (s *Store) UpsertSSHTargetRow(row model.SSHTargetRow, updatePassword bool) error {
	if s == nil {
		return fmt.Errorf("audit store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if updatePassword {
		_, err := s.db.Exec(`INSERT INTO ssh_targets (
			id, host, port, ssh_user, auth_type, key_path, password_cipher, password_hash, known_hosts_path, blocked_clients_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			host = excluded.host,
			port = excluded.port,
			ssh_user = excluded.ssh_user,
			auth_type = excluded.auth_type,
			key_path = excluded.key_path,
			password_cipher = excluded.password_cipher,
			password_hash = excluded.password_hash,
			known_hosts_path = excluded.known_hosts_path,
			blocked_clients_json = excluded.blocked_clients_json,
			updated_at = excluded.updated_at`,
			row.ID, row.Host, row.Port, row.SSHUser, row.AuthType, row.KeyPath, row.PasswordCipher, row.PasswordHash, row.KnownHostsPath, row.BlockedClientsJSON, row.CreatedAt, row.UpdatedAt)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO ssh_targets (
		id, host, port, ssh_user, auth_type, key_path, password_cipher, password_hash, known_hosts_path, blocked_clients_json, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		host = excluded.host,
		port = excluded.port,
		ssh_user = excluded.ssh_user,
		auth_type = excluded.auth_type,
		key_path = excluded.key_path,
		known_hosts_path = excluded.known_hosts_path,
		blocked_clients_json = excluded.blocked_clients_json,
		updated_at = excluded.updated_at`,
		row.ID, row.Host, row.Port, row.SSHUser, row.AuthType, row.KeyPath, row.KnownHostsPath, row.BlockedClientsJSON, row.CreatedAt, row.UpdatedAt)
	return err
}

func (s *Store) SSHTargetExists(id string) (bool, error) {
	if s == nil {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var found string
	err := s.db.QueryRow(`SELECT id FROM ssh_targets WHERE id = ?`, strings.TrimSpace(id)).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) ListSSHTargetRows() ([]model.SSHTargetRow, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, host, port, ssh_user, auth_type, key_path, password_cipher, password_hash, known_hosts_path, blocked_clients_json, created_at, updated_at
		FROM ssh_targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.SSHTargetRow, 0)
	for rows.Next() {
		row, err := scanTargetRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (s *Store) GetSSHTargetRow(id string) (model.SSHTargetRow, error) {
	var row model.SSHTargetRow
	if s == nil {
		return row, fmt.Errorf("ssh target not found: %s", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := s.db.QueryRow(`SELECT id, host, port, ssh_user, auth_type, key_path, password_cipher, password_hash, known_hosts_path, blocked_clients_json, created_at, updated_at
		FROM ssh_targets WHERE id = ?`, strings.TrimSpace(id))
	row, err := scanTargetRow(raw)
	if err == sql.ErrNoRows {
		return row, fmt.Errorf("ssh target not found: %s", id)
	}
	return row, err
}

func scanTargetRow(row scanner) (model.SSHTargetRow, error) {
	var target model.SSHTargetRow
	var keyPath, passwordCipher, passwordHash, knownHostsPath, blockedJSON sql.NullString
	err := row.Scan(
		&target.ID, &target.Host, &target.Port, &target.SSHUser, &target.AuthType,
		&keyPath, &passwordCipher, &passwordHash, &knownHostsPath, &blockedJSON,
		&target.CreatedAt, &target.UpdatedAt,
	)
	if err != nil {
		return target, err
	}
	target.KeyPath = keyPath.String
	target.PasswordCipher = passwordCipher.String
	target.PasswordHash = passwordHash.String
	target.KnownHostsPath = knownHostsPath.String
	target.BlockedClientsJSON = blockedJSON.String
	return target, nil
}
