package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/mayjain/aegis/internal/ipc"
)

type Shim struct {
	conn     net.Conn
	shimID   string
	agentID  string
	toolName string
	pending  sync.Map // map[requestID]chan *ipc.AegisEnvelope
	done     chan struct{}
}

func (s *Shim) register() error {
	env := &ipc.AegisEnvelope{
		Type:     "register",
		ShimID:   s.shimID,
		AgentID:  s.agentID,
		ToolName: s.toolName,
	}
	if err := ipc.WriteEnvelope(s.conn, env); err != nil {
		return fmt.Errorf("send registration: %w", err)
	}

	resp, err := ipc.ReadEnvelope(s.conn)
	if err != nil {
		return fmt.Errorf("read registration response: %w", err)
	}
	if resp.Type != "registered" {
		if resp.Error != "" {
			return fmt.Errorf("registration rejected: %s", resp.Error)
		}
		return fmt.Errorf("unexpected response type: %s", resp.Type)
	}
	return nil
}

func (s *Shim) readLoop() {
	defer close(s.done)
	for {
		env, err := ipc.ReadEnvelope(s.conn)
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		if ch, ok := s.pending.Load(env.RequestID); ok {
			ch.(chan *ipc.AegisEnvelope) <- env
		}
	}
}

func (s *Shim) sendRequest(mcpMsg json.RawMessage) (*ipc.AegisEnvelope, error) {
	requestID := uuid.New().String()
	ch := make(chan *ipc.AegisEnvelope, 1)
	s.pending.Store(requestID, ch)
	defer s.pending.Delete(requestID)

	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     s.shimID,
		AgentID:    s.agentID,
		ToolName:   s.toolName,
		RequestID:  requestID,
		MCPMessage: mcpMsg,
	}
	if err := ipc.WriteEnvelope(s.conn, env); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("daemon disconnected")
		}
		return resp, nil
	case <-s.done:
		return nil, fmt.Errorf("daemon disconnected")
	}
}

func main() {
	toolName := flag.String("tool", "", "downstream tool name (required)")
	agentID := flag.String("agent-id", "", "agent ID (required)")
	socketPath := flag.String("socket", "/tmp/aegis.sock", "daemon Unix socket path")
	flag.Parse()

	if *toolName == "" || *agentID == "" {
		fmt.Fprintln(os.Stderr, "aegis-shim: --tool and --agent-id are required")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: daemon not running at %s: %v\n", *socketPath, err)
		os.Exit(1)
	}
	defer conn.Close()

	s := &Shim{
		conn:     conn,
		shimID:   uuid.New().String(),
		agentID:  *agentID,
		toolName: *toolName,
		done:     make(chan struct{}),
	}

	if err := s.register(); err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: %v\n", err)
		os.Exit(1)
	}

	go s.readLoop()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			fmt.Fprintln(os.Stderr, "aegis-shim: invalid JSON on stdin, skipping")
			continue
		}

		resp, err := s.sendRequest(json.RawMessage(line))
		if err != nil {
			fmt.Fprintf(os.Stderr, "aegis-shim: %v\n", err)
			os.Exit(1)
		}
		if resp.MCPMessage != nil {
			fmt.Println(string(resp.MCPMessage))
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: stdin read error: %v\n", err)
		os.Exit(1)
	}
}
