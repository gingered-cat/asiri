package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/gingered-cat/asiri/internal/approve"
	"github.com/gingered-cat/asiri/internal/domain"
	"github.com/gingered-cat/asiri/internal/mcpserver"
	"github.com/gingered-cat/asiri/internal/server"
	"github.com/gingered-cat/asiri/internal/skill"
)

// asiri mcp: an MCP server on stdio for an agent's profile. stdout carries
// the protocol, so nothing else may print there.
func mcpCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	profile := profileFlag(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	log.SetOutput(os.Stderr)
	c, p, err := connect(*profile)
	if err != nil {
		return err
	}
	if who, err := c.WhoAmI(ctx); err == nil && who.Role == domain.RoleOwner {
		fmt.Fprintf(os.Stderr, "asiri mcp: profile %q is an owner; give agents their own profile (asiri clients add claude)\n", p.Name)
	}
	rexServer := os.Getenv("ASIRI_REX_SERVER")
	s := &mcpserver.Server{API: c, Version: server.Version, Approver: func(w io.Writer) approve.Approver {
		// No terminal here: stdin is the protocol. Rex, then "asiri approve ID".
		return approve.Chain{approve.Rex{Server: rexServer, Out: w}, approve.Wait{API: c, Out: w}}
	}}
	return s.MCP().Run(ctx, &mcp.StdioTransport{})
}

// asiri skill: print the Agent Skill (SKILL.md).
func skillCmd(_ context.Context, args []string) error {
	if len(args) > 0 {
		return usageError{"no arguments; redirect it, e.g. asiri skill > ~/.claude/skills/asiri/SKILL.md"}
	}
	_, err := io.WriteString(os.Stdout, skill.Text)
	return err
}
