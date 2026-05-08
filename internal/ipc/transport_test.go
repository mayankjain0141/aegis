package ipc

import (
	"encoding/json"
	"io"
	"net"
	"testing"
)

func TestWriteReadEnvelope_RoundTrip(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	original := &AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_001",
		AgentID:    "claude-main",
		ToolName:   "shell-mcp",
		RequestID:  "req_abc123",
		MCPMessage: json.RawMessage(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":1}`),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- WriteEnvelope(client, original)
	}()

	received, err := ReadEnvelope(server)
	if err != nil {
		t.Fatalf("ReadEnvelope failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("WriteEnvelope failed: %v", err)
	}

	if received.Type != original.Type {
		t.Errorf("Type mismatch: got %q, want %q", received.Type, original.Type)
	}
	if received.ShimID != original.ShimID {
		t.Errorf("ShimID mismatch: got %q, want %q", received.ShimID, original.ShimID)
	}
	if received.AgentID != original.AgentID {
		t.Errorf("AgentID mismatch: got %q, want %q", received.AgentID, original.AgentID)
	}
	if received.RequestID != original.RequestID {
		t.Errorf("RequestID mismatch: got %q, want %q", received.RequestID, original.RequestID)
	}
	if string(received.MCPMessage) != string(original.MCPMessage) {
		t.Errorf("MCPMessage mismatch: got %s, want %s", received.MCPMessage, original.MCPMessage)
	}
}

func TestWriteReadEnvelope_MultipleMessages(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	messages := []*AegisEnvelope{
		{Type: "register", ShimID: "s1", AgentID: "a1", ToolName: "tool1"},
		{Type: "mcp_request", ShimID: "s1", RequestID: "r1", MCPMessage: json.RawMessage(`{"id":1}`)},
		{Type: "mcp_response", ShimID: "s1", RequestID: "r1", MCPMessage: json.RawMessage(`{"id":1,"result":{}}`)},
	}

	go func() {
		for _, msg := range messages {
			if err := WriteEnvelope(client, msg); err != nil {
				t.Errorf("WriteEnvelope failed: %v", err)
				return
			}
		}
	}()

	for i, want := range messages {
		got, err := ReadEnvelope(server)
		if err != nil {
			t.Fatalf("ReadEnvelope[%d] failed: %v", i, err)
		}
		if got.Type != want.Type {
			t.Errorf("[%d] Type: got %q, want %q", i, got.Type, want.Type)
		}
		if got.ShimID != want.ShimID {
			t.Errorf("[%d] ShimID: got %q, want %q", i, got.ShimID, want.ShimID)
		}
	}
}

func TestReadEnvelope_OversizedLength_Rejects(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Write a length prefix that exceeds maxMessageSize
	go func() {
		header := []byte{0x10, 0x00, 0x00, 0x01} // ~268MB, exceeds 256MB limit
		client.Write(header)
		client.Close()
	}()

	_, err := ReadEnvelope(server)
	if err == nil {
		t.Fatal("expected error for oversized message, got nil")
	}
	t.Logf("got expected error: %v", err)
}

func TestReadEnvelope_EOF(t *testing.T) {
	server, client := net.Pipe()
	client.Close()

	_, err := ReadEnvelope(server)
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
	server.Close()
}

func TestWriteReadEnvelope_EmptyMCPMessage(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	original := &AegisEnvelope{
		Type:    "register",
		ShimID:  "s1",
		AgentID: "agent1",
	}

	go func() {
		WriteEnvelope(client, original)
	}()

	received, err := ReadEnvelope(server)
	if err != nil {
		t.Fatalf("ReadEnvelope failed: %v", err)
	}
	if received.MCPMessage != nil {
		t.Errorf("expected nil MCPMessage, got: %s", received.MCPMessage)
	}
}
