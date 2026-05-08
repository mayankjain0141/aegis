// Package main implements a passive MCP traffic logger.
// In the Aegis PoC, we use the official Go MCP SDK instead of sniffing raw traffic.
// This tool exists for debugging: configure it as an MCP server in Claude Code
// to log all messages passing through.
//
// Usage:
//
//	In .cursor/mcp.json, replace a tool server command with:
//	"command": "aegis-sniffer", "args": ["--wrap", "original-command", "--log", "/tmp/mcp.log"]
//
// For the PoC, testdata/mcp_captured.jsonl serves as our golden test fixture.
package main

import "fmt"

func main() {
	fmt.Println("mcp-sniffer: use testdata/mcp_captured.jsonl for golden test data")
	fmt.Println("This tool is a placeholder for future live traffic logging.")
}
