package trace

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWAL_WriteAndReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	w, err := NewWALWriter(path, testLogger())
	if err != nil {
		t.Fatalf("NewWALWriter: %v", err)
	}

	events := []*TraceEvent{
		makeEvent("tool_a"),
		makeEvent("tool_b"),
		makeEvent("tool_c"),
	}

	for _, ev := range events {
		if err := w.Write(ev); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	w.Close()

	// Verify file content is valid NDJSON
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		var ev TraceEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("line %d unmarshal: %v", count+1, err)
		}
		if ev.Tool != events[count].Tool {
			t.Errorf("line %d tool = %q, want %q", count+1, ev.Tool, events[count].Tool)
		}
		count++
	}
	if count != 3 {
		t.Errorf("line count = %d, want 3", count)
	}
}

func TestWAL_RotatesAt100MB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	// Use 1KB max to test rotation quickly
	w, err := NewWALWriterWithSize(path, 1024, testLogger())
	if err != nil {
		t.Fatalf("NewWALWriter: %v", err)
	}

	ev := &TraceEvent{
		SessionID: "sess-001",
		RequestID: "req-001",
		AgentID:   "agent-001",
		Timestamp: time.Now(),
		Tool:      "big_tool_name_for_padding",
		RiskScore: 0.9,
		Decision:  "allow",
		Mode:      "enforce",
		LatencyMs: 42,
		ArgsHash:  strings.Repeat("x", 200),
	}

	// Write enough to exceed 1KB
	for i := 0; i < 20; i++ {
		if err := w.Write(ev); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	w.Close()

	// Backup file should exist
	backupPath := path + ".1"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("expected backup file after rotation, not found")
	}

	// Current WAL should be smaller than maxSize
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat current wal: %v", err)
	}
	if info.Size() > 1024 {
		t.Errorf("current wal size = %d, expected <= 1024 after rotation", info.Size())
	}
}

func TestWAL_CorruptLine_Skipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	// Write a mix of valid JSON and corrupt lines manually
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	validEvent := makeEvent("valid_tool")
	validJSON, _ := json.Marshal(validEvent)

	f.Write(validJSON)
	f.Write([]byte("\n"))
	f.Write([]byte("this is not json at all\n"))
	f.Write([]byte("{broken json\n"))
	f.Write(validJSON)
	f.Write([]byte("\n"))
	f.Close()

	// Open with WALWriter and verify parseWALLine behavior
	rf, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rf.Close()

	scanner := bufio.NewScanner(rf)
	parsed := 0
	corrupt := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		_, err := parseWALLine(line)
		if err != nil {
			corrupt++
		} else {
			parsed++
		}
	}

	if parsed != 2 {
		t.Errorf("parsed = %d, want 2", parsed)
	}
	if corrupt != 2 {
		t.Errorf("corrupt = %d, want 2", corrupt)
	}
}

func TestWAL_Truncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wal")

	w, err := NewWALWriter(path, testLogger())
	if err != nil {
		t.Fatalf("NewWALWriter: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := w.Write(makeEvent("truncate_test")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if w.Size() == 0 {
		t.Fatal("expected non-zero size before truncate")
	}

	if err := w.Truncate(); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	if w.Size() != 0 {
		t.Errorf("size after truncate = %d, want 0", w.Size())
	}

	// File should be empty
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("file size after truncate = %d, want 0", info.Size())
	}

	// Should still be writable after truncate
	if err := w.Write(makeEvent("after_truncate")); err != nil {
		t.Fatalf("Write after truncate: %v", err)
	}
	if w.Size() == 0 {
		t.Error("expected non-zero size after writing post-truncate")
	}

	w.Close()
}
