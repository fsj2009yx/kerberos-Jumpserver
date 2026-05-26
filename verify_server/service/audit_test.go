package service

import (
	"os"
	"path/filepath"
	"testing"

	"security-project/verify_server/service/audit/model"
	auditrepo "security-project/verify_server/service/audit/repository"
)

func TestAuditStorePersistsSQLiteRecords(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := auditrepo.NewStore(dbPath)
	if err != nil {
		t.Fatalf("new audit store: %v", err)
	}

	for _, rec := range []model.Record{
		{Kind: "auth", EventType: "AP_REQ", ClientID: "CLIENT_1", Result: "ok"},
		{Kind: "pty", EventType: "APP_REQ", ClientID: "CLIENT_1", TargetID: "prod-1", PTYSessionID: 7, FrameType: "input", PayloadB64: auditPayload([]byte("ls\n")), Result: "ok"},
		{Kind: "pty", EventType: "APP_REP", ClientID: "CLIENT_1", TargetID: "prod-1", PTYSessionID: 7, FrameType: "output", PayloadB64: auditPayload([]byte("ok\n")), Result: "ok"},
	} {
		if err := store.Append(rec); err != nil {
			t.Fatalf("append audit record: %v", err)
		}
	}

	records, err := store.Records(10, nil)
	if err != nil {
		t.Fatalf("query audit records: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
	if records[0].ID != 3 || records[1].ID != 2 || records[2].ID != 1 {
		t.Fatalf("expected newest-first records, got ids %d, %d, %d", records[0].ID, records[1].ID, records[2].ID)
	}
	if records[0].PrevHash != records[1].RecordHash {
		t.Fatalf("hash chain not persisted: prev=%q previous record hash=%q", records[0].PrevHash, records[1].RecordHash)
	}

	ptyRecords, err := store.Records(10, func(rec model.Record) bool {
		return rec.Kind == "pty" && rec.PTYSessionID == 7
	})
	if err != nil {
		t.Fatalf("query filtered audit records: %v", err)
	}
	if len(ptyRecords) != 2 {
		t.Fatalf("expected 2 pty records, got %d", len(ptyRecords))
	}
	lastHash := records[0].RecordHash
	if err := store.Close(); err != nil {
		t.Fatalf("close audit store: %v", err)
	}

	reopened, err := auditrepo.NewStore(dbPath)
	if err != nil {
		t.Fatalf("reopen audit store: %v", err)
	}
	defer reopened.Close()
	if err := reopened.Append(model.Record{Kind: "auth", EventType: "APP_REQ", ClientID: "CLIENT_1", Result: "fail", ErrorCode: "ERR_TEST"}); err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	records, err = reopened.Records(1, nil)
	if err != nil {
		t.Fatalf("query after reopen: %v", err)
	}
	if len(records) != 1 || records[0].ID != 4 || records[0].PrevHash != lastHash {
		t.Fatalf("reopened store did not continue hash chain/id: records=%+v last_hash=%q", records, lastHash)
	}
	if stat, err := os.Stat(dbPath); err != nil || stat.Size() == 0 {
		t.Fatalf("expected sqlite db on disk, stat=%v err=%v", stat, err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); !os.IsNotExist(err) {
			t.Fatalf("expected no sqlite wal/shm sidecar %s, err=%v", dbPath+suffix, err)
		}
	}
}
