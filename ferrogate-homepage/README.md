# FerroGate Homepage

Static commercial homepage and lightweight docs for the GitHub repository
website link.

The GitHub Pages workflow publishes this directory as:

```text
https://lianluo-esign.github.io/ferrogate/
```

The FerroGate runtime also embeds these pages:

- `index.html` for `/` and `/index.html`
- `docs.html` for `/docs` and `/docs.html`

This keeps the product landing page and quick-start documentation aligned
between the repository website and a running gateway.

The standalone vector logo lives at `assets/ferrogate-logo.svg`. The embedded
runtime pages inline the same mark so they do not depend on a separate static
asset route.
