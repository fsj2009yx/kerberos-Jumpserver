package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"security-project/verify_server/config"
	"security-project/verify_server/service/audit/model"

	"golang.org/x/crypto/bcrypt"
)

func NormalizeClientList(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func LegacyBlockedClients(clientDB []config.ClientCertEntry, allowed []string) []string {
	allowedSet := make(map[string]bool, len(allowed))
	for _, id := range NormalizeClientList(allowed) {
		allowedSet[id] = true
	}
	out := make([]string, 0)
	for _, client := range clientDB {
		id := strings.TrimSpace(client.ID)
		if id != "" && !allowedSet[id] {
			out = append(out, id)
		}
	}
	return out
}

func (m *Manager) UpsertSSHTarget(target config.SSHTarget) error {
	if m == nil || m.repo == nil {
		return errors.New("audit manager is nil")
	}
	exists, err := m.repo.SSHTargetExists(target.ID)
	if err != nil {
		return err
	}
	target, err = normalizeTarget(target, !exists)
	if err != nil {
		return err
	}

	row, updatePassword, err := m.targetRow(target)
	if err != nil {
		return err
	}
	return m.repo.UpsertSSHTargetRow(row, updatePassword)
}

func (m *Manager) ListSSHTargets() ([]model.SSHTargetView, error) {
	if m == nil || m.repo == nil {
		return nil, nil
	}
	rows, err := m.repo.ListSSHTargetRows()
	if err != nil {
		return nil, err
	}
	out := make([]model.SSHTargetView, 0, len(rows))
	for _, row := range rows {
		out = append(out, targetView(row))
	}
	return out, nil
}

func (m *Manager) GetSSHTarget(id string, includePassword bool) (config.SSHTarget, error) {
	var target config.SSHTarget
	if m == nil || m.repo == nil {
		return target, fmt.Errorf("ssh target not found: %s", id)
	}
	row, err := m.repo.GetSSHTargetRow(id)
	if err != nil {
		return target, err
	}
	target = config.SSHTarget{
		ID:             row.ID,
		Host:           row.Host,
		Port:           row.Port,
		SSHUser:        row.SSHUser,
		AuthType:       row.AuthType,
		KeyPath:        row.KeyPath,
		KnownHostsPath: row.KnownHostsPath,
		BlockedClients: decodeStringList(row.BlockedClientsJSON),
	}
	if includePassword && row.PasswordCipher != "" {
		password, err := decryptTargetPassword(m.targetKey, row.PasswordCipher)
		if err != nil {
			return target, err
		}
		target.Password = password
	}
	return target, nil
}

func (m *Manager) SSHTargetPassword(id string) (string, error) {
	target, err := m.GetSSHTarget(id, true)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(target.Password) == "" {
		return "", fmt.Errorf("ssh target %s has no stored password", id)
	}
	return target.Password, nil
}

func (m *Manager) UpdateBlockedClients(id string, blocked []string) ([]string, error) {
	target, err := m.GetSSHTarget(id, false)
	if err != nil {
		return nil, err
	}
	target.BlockedClients = blocked
	if err := m.UpsertSSHTarget(target); err != nil {
		return nil, err
	}
	return NormalizeClientList(blocked), nil
}

func normalizeTarget(target config.SSHTarget, passwordRequired bool) (config.SSHTarget, error) {
	target.ID = strings.TrimSpace(target.ID)
	target.Host = strings.TrimSpace(target.Host)
	target.SSHUser = strings.TrimSpace(target.SSHUser)
	target.AuthType = strings.TrimSpace(target.AuthType)
	target.KeyPath = strings.TrimSpace(target.KeyPath)
	target.PasswordPath = strings.TrimSpace(target.PasswordPath)
	target.KnownHostsPath = strings.TrimSpace(target.KnownHostsPath)
	target.BlockedClients = NormalizeClientList(target.BlockedClients)
	if target.AuthType == "" {
		target.AuthType = "password"
	}
	if target.Port == 0 {
		target.Port = 22
	}
	var missing []string
	if target.ID == "" {
		missing = append(missing, "id")
	}
	if target.Host == "" {
		missing = append(missing, "host")
	}
	if target.Port <= 0 {
		return target, errors.New("port must be greater than 0")
	}
	if target.SSHUser == "" {
		missing = append(missing, "ssh_user")
	}
	switch target.AuthType {
	case "password":
		if passwordRequired && strings.TrimSpace(target.Password) == "" && strings.TrimSpace(target.PasswordPath) == "" {
			missing = append(missing, "password")
		}
	case "private_key":
		if target.KeyPath == "" {
			missing = append(missing, "key_path")
		}
	default:
		return target, fmt.Errorf("auth_type unsupported: %s", target.AuthType)
	}
	if len(missing) > 0 {
		return target, fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}
	return target, nil
}

func (m *Manager) targetRow(target config.SSHTarget) (model.SSHTargetRow, bool, error) {
	blockedJSON, err := json.Marshal(target.BlockedClients)
	if err != nil {
		return model.SSHTargetRow{}, false, err
	}
	row := model.SSHTargetRow{
		ID:                 target.ID,
		Host:               target.Host,
		Port:               target.Port,
		SSHUser:            target.SSHUser,
		AuthType:           target.AuthType,
		KeyPath:            target.KeyPath,
		KnownHostsPath:     target.KnownHostsPath,
		BlockedClientsJSON: string(blockedJSON),
		CreatedAt:          time.Now().Unix(),
		UpdatedAt:          time.Now().Unix(),
	}
	if strings.TrimSpace(target.Password) == "" {
		return row, false, nil
	}
	cipherText, err := encryptTargetPassword(m.targetKey, target.Password)
	if err != nil {
		return row, false, err
	}
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(target.Password), bcrypt.DefaultCost)
	if err != nil {
		return row, false, err
	}
	row.PasswordCipher = cipherText
	row.PasswordHash = string(hashBytes)
	return row, true, nil
}

func targetView(row model.SSHTargetRow) model.SSHTargetView {
	return model.SSHTargetView{
		ID:             row.ID,
		Host:           row.Host,
		Port:           row.Port,
		SSHUser:        row.SSHUser,
		AuthType:       row.AuthType,
		KeyPath:        row.KeyPath,
		KnownHostsPath: row.KnownHostsPath,
		BlockedClients: decodeStringList(row.BlockedClientsJSON),
		PasswordSet:    row.PasswordCipher != "",
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}

func decodeStringList(raw string) []string {
	var items []string
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return []string{}
	}
	return NormalizeClientList(items)
}
