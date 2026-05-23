package service

import (
	"fmt"

	"security-project/verify_server/config"
)

func (s *Service) lookupSSHTarget(id string) (config.SSHTarget, error) {
	for _, target := range s.Config.SSHTargets {
		if target.ID == id {
			return target, nil
		}
	}
	return config.SSHTarget{}, fmt.Errorf("ssh target not found: %s", id)
}

func checkTargetPermission(clientID string, target config.SSHTarget) error {
	for _, allowed := range target.AllowedClients {
		if allowed == clientID {
			return nil
		}
	}
	return fmt.Errorf("client %s is not allowed to access target %s", clientID, target.ID)
}
