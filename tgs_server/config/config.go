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

const DefaultPath = "tgs_server/config.json"

type ServiceEntry struct {
	IDV    string `json:"id_v"`
	KVPath string `json:"k_v_path,omitempty"`
	KVHex  string `json:"k_v_hex,omitempty"`
	Addr   string `json:"addr,omitempty"`
}

type Config struct {
	NodeID            string         `json:"node_id"`
	ListenHost        string         `json:"listen_host"`
	ListenPort        int            `json:"listen_port"`
	WebUIHost         string         `json:"webui_host"`
	WebUIPort         int            `json:"webui_port"`
	AntiReplayWindow  int            `json:"anti_replay_window_size"`
	TicketLifetimeSec uint32         `json:"ticket_lifetime_sec"`
	MaxPayloadBytes   uint32         `json:"max_payload_bytes"`
	ReadTimeoutSec    int            `json:"read_timeout_sec"`
	CertPath          string         `json:"cert_path,omitempty"`
	PrivKeyPath       string         `json:"privkey_path,omitempty"`
	LogLevel          string         `json:"log_level"`
	LogFile           string         `json:"log_file,omitempty"`
	SecurityLogFile   string         `json:"security_log_file,omitempty"`
	KTGSPath          string         `json:"k_tgs_path,omitempty"`
	KTGSHex           string         `json:"k_tgs_hex,omitempty"`
	KVPath            string         `json:"k_v_path,omitempty"`
	KVHex             string         `json:"k_v_hex,omitempty"`
	ServiceDB         []ServiceEntry `json:"services"`
}

func (s *ServiceEntry) UnmarshalJSON(raw []byte) error {
	type serviceEntry ServiceEntry
	aux := struct {
		*serviceEntry
		LegacyKVPath string `json:"kv_path"`
		LegacyKVHex  string `json:"kv_hex"`
	}{serviceEntry: (*serviceEntry)(s)}
	if err := json.Unmarshal(raw, &aux); err != nil {
		return err
	}
	if s.KVPath == "" {
		s.KVPath = aux.LegacyKVPath
	}
	if s.KVHex == "" {
		s.KVHex = aux.LegacyKVHex
	}
	return nil
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	log.Infof("[TGS] loading config path=%s", path)
	b, err := os.ReadFile(path)
	if err != nil {
		log.Errorf("[TGS] read config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Errorf("[TGS] parse config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		log.Errorf("[TGS] validate config failed path=%s err=%v", path, err)
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}
	log.Infof("[TGS] config loaded path=%s node_id=%s listen=%s:%d webui=%s:%d services=%d", path, cfg.NodeID, cfg.ListenHost, cfg.ListenPort, cfg.WebUIHost, cfg.WebUIPort, len(cfg.ServiceDB))
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
	if c.AntiReplayWindow <= 0 {
		return errors.New("anti_replay_window_size must be greater than 0")
	}
	if c.TicketLifetimeSec == 0 {
		return errors.New("ticket_lifetime_sec must be greater than 0")
	}
	if c.MaxPayloadBytes == 0 {
		return errors.New("max_payload_bytes must be greater than 0")
	}
	if c.ReadTimeoutSec <= 0 {
		return errors.New("read_timeout_sec must be greater than 0")
	}
	if strings.TrimSpace(c.KTGSPath) == "" && strings.TrimSpace(c.KTGSHex) == "" {
		missing = append(missing, "k_tgs_path or k_tgs_hex")
	}
	if len(c.ServiceDB) == 0 {
		return errors.New("services is empty")
	}
	for i := range c.ServiceDB {
		prefix := fmt.Sprintf("services[%d]", i)
		if strings.TrimSpace(c.ServiceDB[i].IDV) == "" {
			missing = append(missing, prefix+".id_v")
		}
		if c.ServiceDB[i].KVPath == "" && c.KVPath != "" {
			c.ServiceDB[i].KVPath = c.KVPath
		}
		if c.ServiceDB[i].KVHex == "" && c.KVHex != "" {
			c.ServiceDB[i].KVHex = c.KVHex
		}
		if strings.TrimSpace(c.ServiceDB[i].KVPath) == "" && strings.TrimSpace(c.ServiceDB[i].KVHex) == "" {
			missing = append(missing, prefix+".k_v_path or "+prefix+".k_v_hex")
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
	ensureFileDir(c.KTGSPath)
	ensureFileDir(c.KVPath)
	for _, service := range c.ServiceDB {
		ensureFileDir(service.KVPath)
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
	if err := krb.EnsureDir(dir); err != nil {
		log.Warnf("[TGS] ensure config directory failed path=%s dir=%s err=%v", path, dir, err)
		return
	}
	log.Debugf("[TGS] config directory ready path=%s dir=%s", path, dir)
}
