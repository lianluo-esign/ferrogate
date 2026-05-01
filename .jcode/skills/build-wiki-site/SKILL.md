# Build FerroGate Wiki Static Site

Use this skill whenever the user asks to edit, build, preview, or publish the FerroGate wiki/static documentation site.

## Repository layout

- `wiki/`: Obsidian vault and Markdown source of truth.
- `wiki-site/`: Quartz static site generator project.
- `wiki-site/public/`: generated static HTML output, not meant to be hand-edited.
- `scripts/build-wiki-site.sh`: canonical build/serve/clean entrypoint.

## Standard workflow

1. Edit or add Markdown notes under `wiki/`.
2. Prefer Obsidian wiki links: `[[path/to/note|Label]]`.
3. Keep product decisions in `wiki/05-decisions/` as ADRs.
4. Build the static site:

   ```bash
   ./scripts/build-wiki-site.sh build
   ```

5. Preview locally when needed:

   ```bash
   ./scripts/build-wiki-site.sh serve
   ```

6. Commit source changes in `wiki/`, Quartz config changes in `wiki-site/`, and script changes in `scripts/`.

## Validation checklist

- `./scripts/build-wiki-site.sh build` exits successfully.
- `wiki-site/public/index.html` exists after build.
- No generated `wiki-site/public/` files are committed unless explicitly requested.
- Keep GitHub workflow files out unless the GitHub token has `workflow` scope and the user asks for CI.
