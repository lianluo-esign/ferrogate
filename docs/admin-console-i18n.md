# Admin Console i18n — contributor guide (#346, #348)

The console ships in **English (`en`)** and **Simplified Chinese (`zh-CN`)**.
Every operator-facing string — labels, options, validation, toasts, tooltips,
accessible names, skip links — comes from a typed catalog. This page is the
contract for adding to it: key naming, namespace ownership, the Chinese
glossary, and how to add a locale.

The runtime itself (`admin-console/src/i18n/`) is documented in the module
headers; this is the *authoring* guide.

## The shape of a key

Keys are **flat and dot-namespaced** — `"page.siteDomains.col.hostname"`, not a
nested object. Flat keys keep `TranslationKey` a plain string union derived from
the English catalog, so a typo is a `tsc` error rather than a runtime `undefined`.

```
<namespace>.<surface>.<slot>[.<qualifier>]
```

Rules:

- **Semantic, never the English text.** `"resource.action.new"`, never
  `"New"`. English copy is a value, not an identifier.
- **Never concatenate translated fragments.** One key per rendered sentence,
  with `{placeholders}` for the variable parts:
  `"page.siteDomains.toast.bound": "Bound {hostname}.{note}"`. Chinese word
  order is not English word order, so gluing two half-sentences together cannot
  be translated correctly.
- **Placeholders carry values, not copy.** `{hostname}`, `{count}`, `{name}` are
  identifiers or numbers passed through verbatim. If a placeholder needs to hold
  *copy*, resolve that copy to a key first and pass the resolved string.
- **Plurals go through `format.plural`**, not `n === 1 ? "" : "s"`. Chinese has
  one plural category and English has two; the CLDR selector handles both.

## Namespace ownership

| Namespace | Owner | Lives in |
|---|---|---|
| `common.*` | shared words used by 3+ surfaces (yes/no, enabled/disabled, cancel) | `locales/en/bootstrap.ts` |
| `nav.*`, `shell.*` | app shell: sidebar, breadcrumbs, skip link, logout | `locales/en/bootstrap.ts` |
| `auth.*` | login / register / session | `locales/en/bootstrap.ts` |
| `language.*`, `theme.*`, `component.*` | always-visible chrome primitives | `locales/en/bootstrap.ts` |
| `error.*` | backend status/code → generic operator headline (`i18n/errors.ts`) | `locales/en/rest.ts` |
| `validation.*` | client-side validation owned by a `lib/` module, shared by 2+ pages | `locales/en/rest.ts` |
| `dashboard.*` | the operations overview | `locales/en/rest.ts` |
| `resource.*` | the generated CRUD framework + per-resource configs | `locales/en/rest.ts` |
| `page.<route>.*` | one bespoke page each | `locales/en/rest.ts` |

**Bootstrap vs rest is a bundle-budget boundary, not a style choice.** Only the
`bootstrap` subset is eager in the entry chunk so the always-visible chrome
paints with no async hop; everything else is code-split (#393/#394) and the
entry budget is enforced by `npm run check:bundle`. **New page copy goes in
`locales/en/rest.ts`.** Adding to `bootstrap.ts` grows the entry chunk — do it
only for copy that renders before any route resolves, and say so in review.

## Adding copy

1. Add the key + English value to `src/i18n/locales/en/rest.ts`.
2. Add the SAME key to `src/i18n/locales/zh-CN.ts` — check the
   [glossary](#simplified-chinese-glossary) before inventing a term.
3. Render it with `t("<key>", { ...values })` from `useI18n()`.
4. `npx tsc -b` — a missing or misspelled zh-CN key is a compile error
   (`_ZhCatalogIsComplete` in `catalog.ts`, plus `satisfies Messages` on the
   zh-CN value itself).
5. `npx vitest run` — `catalog.test.ts` checks key/placeholder parity and
   `glossary.test.ts` checks terminology.
6. `npm run lint` — `ferrogate/no-untranslated-literal` rejects a literal that
   should have been a key. The file-level allowlist is **empty**; keep it that
   way.

### What must NOT be translated

FerroGate, provider and model names, API paths, identifiers, hashes, code and
config values, user content, and raw server evidence stay byte-for-byte
identical across locales. Where such a value is rendered next to copy, mark it
`translate="no"` so browser auto-translation cannot rewrite it either — as the
error-toast technical detail and the copyable identifier cells do.

Two related honesty rules the console already follows:

- **Never invent a label for an unknown identifier.** Fall back to the raw
  identifier instead (see #343/#344).
- **An already-localized failure is not a server string.** A page that throws an
  `Error` whose message it built with `t()` must throw `LocalizedError`
  (`src/lib/localized-error.ts`), so the error toast shows that precise copy
  instead of replacing it with the generic headline.

### Dates, numbers, money

Use the bound formatters from `useI18n()` — `format.date`, `format.time`,
`format.relativeTime`, `format.number`, `format.tokens`, `format.percent`,
`format.bytes`, `format.currency` — or `useFormatUnix()` for unix-seconds
columns. A bare `toLocaleString()` follows the **browser's** language, not the
console's, and is a bug even though it looks localized.

The one deliberate exception: **audit/evidence timestamps** (`lib/guardrails.ts`,
`components/agent-ops/agent-ops-primitives.tsx`) render UTC ISO strings and must
stay identical across a locale switch.

## Simplified Chinese glossary

The canonical table is **executable**: `src/i18n/glossary.ts`, enforced by
`src/i18n/glossary.test.ts`. If a term gains a second Chinese rendering, the
suite fails and names both keys. The rules it encodes:

| English | 简体中文 | Note |
|---|---|---|
| Tenant / Project / Workspace | 租户 / 项目 / 工作空间 | 工作空间, not 工作区 (that reads as a UI pane) |
| Provider / Model | 提供商 / 模型 | 提供商, not 提供方 |
| Policy / Guardrail policies | 策略 / 护栏策略 | |
| Decision / Decision reason / Verdict | 决策 / 决策原因 / 判定 | |
| Tokens / Cost (USD) | 令牌数 / 费用（美元） | |
| MCP servers | MCP 服务器 | "MCP" is a protocol name — untranslated |
| Agent run(s) | 智能体运行 | **代理 means *proxy*** and is reserved for the proxy sense |
| Assets / Site domains | 资产 / 站点域名 | |
| Revision / Active revision | 修订版本 / 生效修订版本 | 修订 alone reads as the verb |
| Health / Enabled / Disabled | 健康状态 / 已启用 / 已禁用 | |
| Request id / Trace id | 请求 ID / 追踪 ID | uppercase ID |

When one English word genuinely names two different things ("Active" as a
template status vs a served version vs a row state), add the key to
`SENSE_EXCEPTIONS` **with the reason**. The test rejects an exception that no
longer diverges, so the list cannot rot. A synonym you simply prefer is not a
sense difference — unify instead.

## Adding a locale

The type system does most of the work: adding a code to `LOCALES` is a compile
error until every step below is done.

1. Add the code to `LOCALES` in `src/i18n/catalog.ts` and its `LOCALE_META`
   entry (autonym + `htmlLang`).
2. Create `src/i18n/locales/<code>.ts` exporting the full catalog
   `satisfies Messages` — `tsc` lists every missing key.
3. Register its lazy loader in `catalogLoaders` (typed `Record<Locale, …>`, so
   this is a compile error until you do). Keep it a dynamic `import()` so the
   copy lands in its own chunk and NOT in the entry budget.
4. Add a completeness assertion for it next to `_ZhCatalogIsComplete`.
5. Extend `e2e/support/i18n.ts` (`HTML_LANG`, `LOCALE_AUTONYM`) and the
   both-locale route matrix.
6. Write the locale's glossary decisions into `src/i18n/glossary.ts` if it needs
   its own vocabulary rules.

## Browser coverage

- `e2e/i18n-route-matrix.spec.ts` — representative route per acceptance area, in
  both locales, at all three viewports (390×844, 768×1024, 1440×900), asserting
  no mixed-language shell, no document overflow, no clipped primary action.
- `e2e/i18n-route-sweep.spec.ts` — **every** registered route (derived directly
  from `APP_ROUTES` + `RESOURCE_ROUTE_PATHS`, so a new route is covered the day
  it is registered) in both locales at the desktop viewport.
- `e2e/i18n-language-switch.spec.ts` — the switcher, persistence, and `<html lang>`.
