---
title: Development workflow
---

# Development workflow

## Local development

```bash
cargo run -- check
cargo run -- serve
```

Then test:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/v1/models
```

## Documentation workflow

1. Edit notes in `wiki/` with Obsidian.
2. Use wiki links like `[[02-architecture/system-architecture]]`.
3. Build the static site with:

```bash
./scripts/build-wiki-site.sh
```

4. Preview with:

```bash
cd wiki-site
npm run docs:serve
```

## Commit workflow

- Keep product and architecture changes documented in `wiki/`.
- Add Architecture Decision Records for major design changes.
- Keep generated `wiki-site/public/` out of git unless a deployment target explicitly requires it.
