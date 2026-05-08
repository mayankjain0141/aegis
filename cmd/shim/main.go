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
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "aegis-shim: no input on stdin")
		os.Exit(1)
	}
	input := scanner.Bytes()

	if !json.Valid(input) {
		fmt.Fprintln(os.Stderr, "aegis-shim: invalid JSON on stdin")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", defaultSocket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: daemon not running at %s: %v\n", defaultSocket, err)
		os.Exit(1)
	}
	defer conn.Close()

	// Register with the daemon
	regEnv := &ipc.AegisEnvelope{
		Type:    "register",
		ShimID:  "shim_hello",
		AgentID: "hello-test",
	}
	if err := ipc.WriteEnvelope(conn, regEnv); err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: register send failed: %v\n", err)
		os.Exit(1)
	}

	regResp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: register response failed: %v\n", err)
		os.Exit(1)
	}
	if regResp.Type != "registered" {
		fmt.Fprintf(os.Stderr, "aegis-shim: registration rejected: %s\n", regResp.Error)
		os.Exit(1)
	}

	// Send MCP request
	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "shim_hello",
		AgentID:    "hello-test",
		SessionID:  regResp.SessionID,
		MCPMessage: json.RawMessage(input),
	}

	if err := ipc.WriteEnvelope(conn, env); err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: send failed: %v\n", err)
		os.Exit(1)
	}

	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-shim: receive failed: %v\n", err)
		os.Exit(1)
	}

	if resp.MCPMessage != nil {
		fmt.Println(string(resp.MCPMessage))
	}
}
