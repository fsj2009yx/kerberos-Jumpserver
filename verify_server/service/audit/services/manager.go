package services

import (
	"security-project/verify_server/service/audit/model"
	"security-project/verify_server/service/audit/repository"
)

type Manager struct {
	repo      *repository.Store
	targetKey [32]byte
}

func NewManager(repo *repository.Store, nodeID string, kv [8]byte) *Manager {
	return &Manager{
		repo:      repo,
		targetKey: DeriveTargetPasswordKey(nodeID, kv),
	}
}

func (m *Manager) Close() error {
	if m == nil || m.repo == nil {
		return nil
	}
	return m.repo.Close()
}

func (m *Manager) Append(rec model.Record) error {
	if m == nil || m.repo == nil {
		return nil
	}
	return m.repo.Append(rec)
}

func (m *Manager) Records(limit int, filter func(model.Record) bool) ([]model.Record, error) {
	if m == nil || m.repo == nil {
		return nil, nil
	}
	return m.repo.Records(limit, filter)
}
