package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ShellInput struct {
	Command string `json:"command"`
}

type FileReadInput struct {
	Path string `json:"path"`
}

type FileDeleteInput struct {
	Path string `json:"path"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "aegis-real-tool", Version: "0.1.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "shell_exec",
		Description: "Execute a shell command and return stdout",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ShellInput) (*mcp.CallToolResult, any, error) {
		cmd := exec.CommandContext(ctx, "sh", "-c", input.Command)
		output, err := cmd.CombinedOutput()
		text := strings.TrimSpace(string(output))
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("error: %v\n%s", err, text)},
				},
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: text},
			},
		}, nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_read",
		Description: "Read a file and return its contents",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FileReadInput) (*mcp.CallToolResult, any, error) {
		data, err := os.ReadFile(input.Path)
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("read error: %v", err)},
				},
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(data)},
			},
		}, nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "file_delete",
		Description: "Delete a file at the given path",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input FileDeleteInput) (*mcp.CallToolResult, any, error) {
		if err := os.Remove(input.Path); err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("delete error: %v", err)},
				},
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("deleted: %s", input.Path)},
			},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
