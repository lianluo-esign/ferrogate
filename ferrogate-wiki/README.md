# FerroGate Wiki Monorepo

This repository contains the documentation knowledge base and static site tooling for FerroGate.

## Layout

- `wiki/`: Obsidian vault and Markdown source of truth.
- `wiki-site/`: Quartz static site generator project.
- `wiki-site/public/`: generated static site output, ignored by git.
- `scripts/build-wiki-site.sh`: canonical build, serve, and clean tool.
- `.jcode/skills/build-wiki-site/`: Jcode skill that documents the wiki build workflow.

## Build

```bash
./scripts/build-wiki-site.sh build
```

## Preview

```bash
./scripts/build-wiki-site.sh serve
```

Then open <http://localhost:8080/>.

## Clean generated output

```bash
./scripts/build-wiki-site.sh clean
```

## Editing workflow

1. Edit Markdown notes in `wiki/` with Obsidian.
2. Use Obsidian links such as `[[02-architecture/system-architecture|System architecture]]`.
3. Keep major design decisions in `wiki/05-decisions/` using ADR notes.
4. Build with Quartz using `./scripts/build-wiki-site.sh build`.
