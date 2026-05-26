package service

import (
	"path/filepath"
	"testing"

	"security-project/verify_server/config"
	auditrepo "security-project/verify_server/service/audit/repository"
	auditservices "security-project/verify_server/service/audit/services"
)

func TestSSHTargetStorePersistsPasswordAndBlockedClients(t *testing.T) {
	store, err := auditrepo.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("new audit store: %v", err)
	}
	manager := auditservices.NewManager(store, "verify_server", [8]byte{'K', 'V', 'K', 'E', 'Y', '1', '2', '3'})
	defer manager.Close()

	target := config.SSHTarget{
		ID:             "prod-1",
		Host:           "127.0.0.1",
		Port:           22,
		SSHUser:        "deploy",
		AuthType:       "password",
		Password:       "secret-pass",
		BlockedClients: []string{"CLIENT_3", "CLIENT_4"},
	}
	if err := manager.UpsertSSHTarget(target); err != nil {
		t.Fatalf("upsert ssh target: %v", err)
	}

	list, err := manager.ListSSHTargets()
	if err != nil {
		t.Fatalf("list ssh targets: %v", err)
	}
	if len(list) != 1 || !list[0].PasswordSet || len(list[0].BlockedClients) != 2 {
		t.Fatalf("unexpected target view: %+v", list)
	}
	password, err := manager.SSHTargetPassword("prod-1")
	if err != nil {
		t.Fatalf("read target password: %v", err)
	}
	if password != "secret-pass" {
		t.Fatalf("unexpected password %q", password)
	}

	target.BlockedClients = []string{"CLIENT_2"}
	target.Password = ""
	if err := manager.UpsertSSHTarget(target); err != nil {
		t.Fatalf("update ssh target: %v", err)
	}
	password, err = manager.SSHTargetPassword("prod-1")
	if err != nil {
		t.Fatalf("read target password after metadata update: %v", err)
	}
	if password != "secret-pass" {
		t.Fatalf("metadata update should preserve password, got %q", password)
	}
	got, err := manager.GetSSHTarget("prod-1", false)
	if err != nil {
		t.Fatalf("get target: %v", err)
	}
	if len(got.BlockedClients) != 1 || got.BlockedClients[0] != "CLIENT_2" {
		t.Fatalf("unexpected blocked clients: %+v", got.BlockedClients)
	}
}
