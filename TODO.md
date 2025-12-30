# GHOST Parallel Mode - Next Steps

## High Priority

- [x] Add parallel mode output support to remaining agents (phantom, interceptor, mindbender, skybreaker, breaker, persistence, scribe)
- [x] Create `/ghost` skill for quick parallel engagement initialization
- [x] Add Claude Code hooks for auto-logging commands to runlog.jsonl

## Medium Priority

- [x] Create `ghost-gather.sh` script to consolidate hunter outputs into unified report
- [x] Add file watcher to watchdog for real-time trigger detection on findings.json changes
- [x] Create `ghost-resume.sh` to resume interrupted engagements from state.json
- [x] Add evidence auto-capture (screenshots, request/response) integration

## Lower Priority

- [ ] Create dashboard view script (`ghost-dashboard.sh`) for real-time engagement monitoring
- [ ] Add MCP server integration for external tool orchestration
- [ ] Write integration tests for parallel mode scripts

## Completed

- [x] Create `/tmp/ghost` directory structure and initialization script
- [x] Create JSON schema templates (state.json, plan.json, findings.json)
- [x] Create `ghost-dispatch.sh` helper script for parallel execution
- [x] Create `ghost-findings.sh` for findings/assets/credentials management
- [x] Create `ghost-watchdog.sh` for auto-dispatch monitoring
- [x] Update COMMAND agent with hunter-gather auto-dispatch logic
- [x] Add parallel output support to SHADOW agent
- [x] Add parallel output support to SPIDER agent
- [x] Update settings.json with parallel mode configuration
- [x] Update CLAUDE.md with parallel mode documentation
- [x] Add parallel mode output support to PHANTOM agent
- [x] Add parallel mode output support to INTERCEPTOR agent
- [x] Add parallel mode output support to MINDBENDER agent
- [x] Add parallel mode output support to SKYBREAKER agent
- [x] Add parallel mode output support to BREAKER agent
- [x] Add parallel mode output support to PERSISTENCE agent
- [x] Add parallel mode output support to SCRIBE agent
- [x] Create `/ghost` skill for engagement initialization
- [x] Create `ghost-gather.sh` for Markdown report generation
- [x] Create `ghost-resume.sh` for resuming interrupted engagements
- [x] Add file watcher to `ghost-watchdog.sh` for findings.json changes
- [x] Create `ghost-evidence.sh` for evidence auto-capture
- [x] Add Claude Code hooks configuration
