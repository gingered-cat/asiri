// Package skill holds asiri's Agent Skill: the rules an agent follows to use
// secrets through asiri.
package skill

import _ "embed"

//go:embed SKILL.md
var Text string
