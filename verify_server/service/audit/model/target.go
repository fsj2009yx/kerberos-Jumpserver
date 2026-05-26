package model

type SSHTargetView struct {
	ID             string   `json:"id"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	SSHUser        string   `json:"ssh_user"`
	AuthType       string   `json:"auth_type"`
	KeyPath        string   `json:"key_path,omitempty"`
	KnownHostsPath string   `json:"known_hosts_path,omitempty"`
	BlockedClients []string `json:"blocked_clients"`
	PasswordSet    bool     `json:"password_set"`
	CreatedAt      int64    `json:"created_at"`
	UpdatedAt      int64    `json:"updated_at"`
}

type SSHTargetRow struct {
	ID                 string
	Host               string
	Port               int
	SSHUser            string
	AuthType           string
	KeyPath            string
	PasswordCipher     string
	PasswordHash       string
	KnownHostsPath     string
	BlockedClientsJSON string
	CreatedAt          int64
	UpdatedAt          int64
}
