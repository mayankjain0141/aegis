package main

import (
	"context"
	"fmt"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ShellInput struct {
	Command string `json:"command"`
}

type FileInput struct {
	Path string `json:"path"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "mock-tool", Version: "0.1.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "shell_exec",
		Description: "Execute a shell command",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ShellInput) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("executed: %s", input.Command)},
			},
		}, nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_read",
		Description: "Read a file",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FileInput) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("contents of: %s", input.Path)},
			},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
