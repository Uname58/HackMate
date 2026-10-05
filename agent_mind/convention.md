# agent_mind — Memory Tree Convention

`agent_mind/` is HackMate's long-term memory tree (mirrors Hermes' `memories/tree/`).

## Structure

```
agent_mind/
├── convention.md          # this file — how the tree is organized
└── <vuln>/                # one folder per vulnerability class: xss, sqli, cmdi, ...
    └── <variant>/         # a variant of that vuln
        ├── skill.md       # PURE KNOWLEDGE — how to find / exploit / defend. NO lab content.
        └── cases/         # concrete cases (labs, real targets)
            └── yyyy-mm-dd-which-attack.txt
```

## Rules

1. **skill.md = pure knowledge.** Methodology, bypass techniques, payload templates, defense. Never contain lab walkthroughs or level-by-level case content.
2. **case = concrete instance.** One file per case, named `yyyy-mm-dd-which-attack.txt`, body:
   ```
   vulnerability name:
   URL:
   parameter(s):
   challenge(if have):
   ```
3. **skill and case are strictly separated.** A lab walkthrough belongs in `cases/`, never inside `skill.md`.

## Short memory (NOT here)

Session-level working state (current target, progress, conversation context) lives in the SQLite short-memory store. `agent_mind/` is long-term knowledge only.
