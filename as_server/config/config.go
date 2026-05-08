package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatedier/golib/log"

	"security-project/common/krb"
)

const DefaultPath = "as_server/config.json"

type ClientEntry struct {
	ID       string `json:"id"`
	KcPath   string `json:"kc_path,omitempty"`
	KcHex    string `json:"kc_hex,omitempty"`
	CertPath string `json:"cert_path,omitempty"`
	ADc      uint32 `json:"adc,omitempty"`
}

type Config struct {
	NodeID            string        `json:"node_id"`
	ListenHost        string        `json:"listen_host"`
	ListenPort        int           `json:"listen_port"`
	WebUIHost         string        `json:"webui_host"`
	WebUIPort         int           `json:"webui_port"`
	ThreadPoolSize    int           `json:"thread_pool_size"`
	AntiReplayWindow  int           `json:"anti_replay_window_size"`
	TicketLifetimeSec uint32        `json:"ticket_lifetime_sec"`
	MaxClients        int           `json:"max_clients"`
	MaxPayloadBytes   uint32        `json:"max_payload_bytes"`
	ReadTimeoutSec    int           `json:"read_timeout_sec"`
	CertPath          string        `json:"cert_path,omitempty"`
	PrivKeyPath       string        `json:"privkey_path,omitempty"`
	LogLevel          string        `json:"log_level"`
	LogFile           string        `json:"log_file,omitempty"`
	SecurityLogFile   string        `json:"security_log_file,omitempty"`
	KtgsPath          string        `json:"k_tgs_path,omitempty"`
	KtgsHex           string        `json:"k_tgs_hex,omitempty"`
	ClientDB          []ClientEntry `json:"client_db"`
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	log.Infof("[AS] loading config path=%s", path)
	b, err := os.ReadFile(path)
	if err != nil {
		log.Errorf("[AS] read config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Errorf("[AS] parse config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		log.Errorf("[AS] validate config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}
	log.Infof("[AS] config loaded node_id=%s listen=%s:%d webui=%s:%d clients=%d", cfg.NodeID, cfg.ListenHost, cfg.ListenPort, cfg.WebUIHost, cfg.WebUIPort, len(cfg.ClientDB))
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
	if c.ListenPort <= 0 {
		return errors.New("listen_port must be greater than 0")
	}
	if c.WebUIPort < 0 {
		return errors.New("webui_port must be greater than or equal to 0")
	}
	if c.ThreadPoolSize <= 0 {
		return errors.New("thread_pool_size must be greater than 0")
	}
	if c.AntiReplayWindow <= 0 {
		return errors.New("anti_replay_window_size must be greater than 0")
	}
	if c.TicketLifetimeSec == 0 {
		return errors.New("ticket_lifetime_sec must be greater than 0")
	}
	if c.MaxClients <= 0 {
		return errors.New("max_clients must be greater than 0")
	}
	if c.MaxPayloadBytes == 0 {
		return errors.New("max_payload_bytes must be greater than 0")
	}
	if c.ReadTimeoutSec <= 0 {
		return errors.New("read_timeout_sec must be greater than 0")
	}
	if strings.TrimSpace(c.KtgsPath) == "" && strings.TrimSpace(c.KtgsHex) == "" {
		missing = append(missing, "k_tgs_path or k_tgs_hex")
	}
	if len(c.ClientDB) == 0 {
		return errors.New("client_db is empty")
	}
	if len(c.ClientDB) > c.MaxClients {
		return fmt.Errorf("client_db has %d entries, exceeds max_clients %d", len(c.ClientDB), c.MaxClients)
	}
	for i, client := range c.ClientDB {
		prefix := fmt.Sprintf("client_db[%d]", i)
		if strings.TrimSpace(client.ID) == "" {
			missing = append(missing, prefix+".id")
		}
		if strings.TrimSpace(client.KcPath) == "" && strings.TrimSpace(client.KcHex) == "" {
			missing = append(missing, prefix+".kc_path or "+prefix+".kc_hex")
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
	ensureFileDir(c.KtgsPath)
	for _, client := range c.ClientDB {
		ensureFileDir(client.KcPath)
		ensureFileDir(client.CertPath)
	}
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
