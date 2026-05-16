package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"security-project/common/krb"
	"security-project/pkg/utils/log"
)

const DefaultPath = "verify_server/config.json"

type ClientCertEntry struct {
	ID       string `json:"id"`
	CertPath string `json:"cert_path,omitempty"`
	Addr     string `json:"addr,omitempty"`
}

type Config struct {
	NodeID           string            `json:"node_id"`
	ListenHost       string            `json:"listen_host"`
	ListenPort       int               `json:"listen_port"`
	WebUIHost        string            `json:"webui_host"`
	WebUIPort        int               `json:"webui_port"`
	AntiReplayWindow int               `json:"anti_replay_window_size"`
	MaxPayloadBytes  uint32            `json:"max_payload_bytes"`
	ReadTimeoutSec   int               `json:"read_timeout_sec"`
	CertPath         string            `json:"cert_path,omitempty"`
	PrivKeyPath      string            `json:"privkey_path,omitempty"`
	LogLevel         string            `json:"log_level"`
	LogFile          string            `json:"log_file,omitempty"`
	SecurityLogFile  string            `json:"security_log_file,omitempty"`
	AuditDBFile      string            `json:"audit_db_file,omitempty"`
	AuditLogFile     string            `json:"audit_log_file,omitempty"` // legacy alias
	KVPath           string            `json:"k_v_path,omitempty"`
	KVHex            string            `json:"k_v_hex,omitempty"`
	PTYShell         string            `json:"pty_shell"`
	PTYDefaultTerm   string            `json:"pty_default_term"`
	CLIWhitelist     []string          `json:"cli_whitelist"`
	ClientDB         []ClientCertEntry `json:"client_db"`
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	log.Infof("[V] loading config path=%s", path)
	b, err := os.ReadFile(path)
	if err != nil {
		log.Errorf("[V] read config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Errorf("[V] parse config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		log.Errorf("[V] validate config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}
	log.Infof("[V] config loaded node_id=%s listen=%s:%d webui=%s:%d clients=%d", cfg.NodeID, cfg.ListenHost, cfg.ListenPort, cfg.WebUIHost, cfg.WebUIPort, len(cfg.ClientDB))
	return &cfg, nil
}

func (c *Config) validate() error {
	var missing []string
	requiredString := func(name, value string) {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	requiredString("node_id", c.NodeID)
	requiredString("listen_host", c.ListenHost)
	if c.WebUIPort > 0 {
		requiredString("webui_host", c.WebUIHost)
	}
	requiredString("log_level", c.LogLevel)
	requiredString("privkey_path", c.PrivKeyPath)
	requiredString("pty_shell", c.PTYShell)
	requiredString("pty_default_term", c.PTYDefaultTerm)
	if c.ListenPort <= 0 {
		return errors.New("listen_port must be greater than 0")
	}
	if c.WebUIPort < 0 {
		return errors.New("webui_port must be greater than or equal to 0")
	}
	if c.AntiReplayWindow <= 0 {
		return errors.New("anti_replay_window_size must be greater than 0")
	}
	if c.MaxPayloadBytes == 0 {
		return errors.New("max_payload_bytes must be greater than 0")
	}
	if c.ReadTimeoutSec <= 0 {
		return errors.New("read_timeout_sec must be greater than 0")
	}
	if strings.TrimSpace(c.KVPath) == "" && strings.TrimSpace(c.KVHex) == "" {
		missing = append(missing, "k_v_path or k_v_hex")
	}
	if len(c.ClientDB) == 0 {
		return errors.New("client_db is empty")
	}
	for i, client := range c.ClientDB {
		if strings.TrimSpace(client.ID) == "" {
			missing = append(missing, fmt.Sprintf("client_db[%d].id", i))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}
	c.ensureConfiguredDirs()
	return nil
}

func (c *Config) ensureConfiguredDirs() {
	ensureFileDir(c.CertPath)
	ensureFileDir(c.PrivKeyPath)
	ensureFileDir(c.LogFile)
	ensureFileDir(c.SecurityLogFile)
	ensureFileDir(c.AuditPath())
	ensureFileDir(c.KVPath)
	for _, client := range c.ClientDB {
		ensureFileDir(client.CertPath)
	}
}

func (c *Config) AuditPath() string {
	if strings.TrimSpace(c.AuditDBFile) != "" {
		return c.AuditDBFile
	}
	return c.AuditLogFile
}

func ensureFileDir(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return
	}
	_ = krb.EnsureDir(dir)
}
