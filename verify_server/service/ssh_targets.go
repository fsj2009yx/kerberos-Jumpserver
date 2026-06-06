package service

import (
	"fmt"
	"strings"

	"security-project/verify_server/config"
)

func (s *Service) lookupSSHTarget(id string) (config.SSHTarget, error) {
	if s == nil || s.audit == nil {
		return config.SSHTarget{}, fmt.Errorf("ssh target not found: %s", id)
	}
	return s.audit.GetSSHTarget(id, true)
}

// checkTargetPermission checks if the clientID is allowed to access the target based on the target's BlockedClients list.
func checkTargetPermission(clientID string, target config.SSHTarget) error {
	for _, blocked := range target.BlockedClients {
		if strings.EqualFold(blocked, clientID) {
			return fmt.Errorf("client %s is blocked from target %s", clientID, target.ID)
		}
	}
	return nil
}
