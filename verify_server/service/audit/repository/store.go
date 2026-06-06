package repository

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

const defaultAuditDBFile = "logs/v_audit.db"

type Store struct {
	path     string
	db       *sql.DB
	mu       sync.Mutex
	nextID   uint64
	lastHash string
}

// NewStore 创建一个新的Store实例，连接到指定路径的SQLite数据库，并确保数据库模式正确。
func NewStore(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = defaultAuditDBFile
	}
	if !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{path: path, db: db, nextID: 1}
	if err := store.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.initTail(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if !strings.HasPrefix(path, "file:") {
		_ = os.Chmod(path, 0o600)
	}
	return store, nil
}

func sqliteDSN(path string) string {
	if strings.HasPrefix(path, "file:") {
		return path
	}
	return fmt.Sprintf("file:%s?mode=rwc&_busy_timeout=5000&_journal_mode=DELETE", filepath.ToSlash(path))
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
