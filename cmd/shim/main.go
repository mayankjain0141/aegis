package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/mayjain/aegis/internal/ipc"
)

const defaultSocket = "/tmp/aegis.sock"

func main() {
	// Read one line of JSON from stdin
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "aegis-shim: no input on stdin")
		os.Exit(1)
	}
	input := scanner.Bytes()

	// Validate it's valid JSON
	if !json.Valid(input) {
		fmt.Fprintln(os.Stderr, "aegis-shim: invalid JSON on stdin")
		os.Exit(1)
	}

	// Connect to daemon
	conn, err := net.Dial("unix", defaultSocket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: daemon not running at %s: %v\n", defaultSocket, err)
		os.Exit(1)
	}
	defer conn.Close()

	// Wrap in envelope and send
	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_hello",
		AgentID:    "hello-test",
		MCPMessage: json.RawMessage(input),
	}

	if err := ipc.WriteEnvelope(conn, env); err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: send failed: %v\n", err)
		os.Exit(1)
	}

	// Read response
	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: receive failed: %v\n", err)
		os.Exit(1)
	}

	// Print MCP message to stdout
	if resp.MCPMessage != nil {
		fmt.Println(string(resp.MCPMessage))
	}
}
