# snortx skill

Agent Skills package for the `snortx` Go project. Loaded by [pi-agent](https://github.com/badlogic/pi-mono), Claude Code, and OpenCode when placed in their skill directories.

## Install

Pick the agent you use:

```bash
# pi-agent (global)
git clone <this repo> ~/.pi/agent/skills/snortx

# Claude Code (global)
git clone <this repo> ~/.claude/skills/snortx

# OpenCode (global)
git clone <this repo> ~/.config/opencode/skills/snortx

# Project-local (any agent — works once the project is trusted)
cp -R . ~/.pi/agent/skills/snortx        # or .claude/skills/ or .agents/skills/
```

After installing, restart your agent. The skill registers as `/skill:snortx` (pi) or is auto-discovered from descriptions in Claude Code / OpenCode.

## Use

Tell your agent:

> "Use the snortx skill to add a new rule option."

or invoke directly:

```
/skill:snortx add a new snort rule option for `byte_extract`
```

## Layout

```
snortx/
├── SKILL.md                    # required: frontmatter + main instructions
├── README.md                   # this file
└── references/
    ├── architecture.md         # package map, data flow, types, concurrency
    ├── cli-commands.md         # every CLI command + flag
    ├── rule-options.md         # supported Snort options reference
    └── api.md                  # REST API endpoints + payloads
```

## Compatibility

Follows the [Agent Skills specification](https://agentskills.io/specification). Works with any harness that scans for `SKILL.md` with `name` + `description` frontmatter.

Validated against:
- pi-agent (`~/.pi/agent/skills/`)
- Claude Code (`~/.claude/skills/` and project `.claude/skills/`)
- OpenCode (`~/.config/opencode/skills/`)

Pi will warn (but still load) if the name doesn't match the directory — the spec requires matching but pi is lenient since shared skill dirs benefit from renaming.