# FerroGate Wiki Site

This directory contains the Quartz static site generator for the FerroGate wiki.

## Content source

The source Markdown vault lives in `../wiki`. Do not manually edit generated files in `public/`.

## Build

From the repository root:

```bash
./scripts/build-wiki-site.sh build
```

From this directory:

```bash
npm run docs:build
```

## Preview

From the repository root:

```bash
./scripts/build-wiki-site.sh serve
```

From this directory:

```bash
npm run docs:serve
```

## Output

Quartz writes generated static files to `public/`, which is ignored by git by default.
