package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any         `json:"result"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			fmt.Fprintf(os.Stderr, "mock-tool-server: bad JSON: %v\n", err)
			continue
		}

		resp := handleRequest(req)
		out, _ := json.Marshal(resp)
		fmt.Fprintln(os.Stdout, string(out))
	}
}

func handleRequest(req jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":   map[string]any{"tools": map[string]any{}},
				"serverInfo":     map[string]any{"name": "mock-tool-server", "version": "1.0.0"},
			},
		}

	case "tools/list":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": []map[string]any{
					{
						"name":        "shell_exec",
						"description": "Execute a shell command",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{"command": map[string]any{"type": "string"}},
							"required":   []string{"command"},
						},
					},
					{
						"name":        "file_read",
						"description": "Read a file",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{"path": map[string]any{"type": "string"}},
							"required":   []string{"path"},
						},
					},
				},
			},
		}

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					"content": []map[string]any{{"type": "text", "text": "parse error: " + err.Error()}},
					"isError": true,
				},
			}
		}

		var text string
		switch params.Name {
		case "shell_exec":
			cmd, _ := params.Arguments["command"].(string)
			text = "executed: " + cmd
		case "file_read":
			path, _ := params.Arguments["path"].(string)
			text = "contents of: " + path
		default:
			text = "unknown tool: " + params.Name
		}

		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": text}},
			},
		}

	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"error": "unsupported method: " + req.Method,
			},
		}
	}
}
