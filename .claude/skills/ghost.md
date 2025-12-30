---
name: ghost
description: Initialize a GHOST parallel engagement for penetration testing
---

# /ghost - Initialize GHOST Parallel Engagement

Initialize a new GHOST penetration testing engagement with parallel mode support.

## Usage

```
/ghost <engagement_name> [target]
```

## Parameters

- `engagement_name`: Name for this engagement (e.g., "htb-machine", "client-pentest")
- `target`: Optional target IP or domain

## What This Does

1. Creates the engagement directory structure at `/tmp/ghost/engagements/<name>/`
2. Initializes state.json, plan.json, and findings.json
3. Sets up hunter working directories for all agents
4. Creates the evidence collection structure
5. Sets the active engagement symlink
6. Outputs environment variables to export

## Instructions

When the user invokes `/ghost`, perform these steps:

1. **Run the initialization script**:
   ```bash
   ~/.claude/scripts/ghost-parallel-init.sh "<engagement_name>" "<target>"
   ```

2. **Display the environment export commands** from the script output so the user can set them.

3. **Confirm initialization** by showing the engagement status:
   ```bash
   export GHOST_ENGAGEMENT="/tmp/ghost/active"
   ~/.claude/scripts/ghost-dispatch.sh status
   ```

4. **Remind the user** of next steps:
   - Export the environment variables
   - Start with `@command - Begin parallel engagement`
   - Or manually start recon with `@shadow - Begin reconnaissance`

## Example

User: `/ghost htb-devvortex 10.10.11.242`

Response:
1. Run init script
2. Show exports:
   ```bash
   export GHOST_ENGAGEMENT="/tmp/ghost/engagements/htb-devvortex"
   export TARGET="10.10.11.242"
   ```
3. Show status
4. Remind: "Run the exports above, then use @command to begin the engagement"
