package aegis

import "embed"

//go:embed policies/phase1-deny.yaml
//go:embed policies/phase1-allow.yaml
//go:embed policies/phase1-escalate.yaml
var embeddedPolicyFiles embed.FS

//go:embed policies/data/commands.yaml
var embeddedCommandDB embed.FS
