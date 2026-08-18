// The Simplified Chinese control-plane glossary (#348).
//
// WHY THIS FILE EXISTS
// --------------------
// The catalogs were migrated page by page over fourteen slices, and nothing
// tied a term used on one page to the same term on another. The result was
// vocabulary drift on exactly the objects the issue enumerates: 41 English
// labels had more than one Chinese rendering — "Workspaces" was 工作空间 in the
// nav and 工作区 on the dashboard, "Provider" was 提供商 in six places and 提供方
// in seven others, and an agent run was 智能体运行, 代理运行 or `Agent 运行`
// depending on which page you were looking at. An operator saw three Chinese
// names for one control-plane object.
//
// This module is the source of truth that stops that recurring. It is data, not
// prose: `glossary.test.ts` enforces it against the real catalogs, so a term
// that GAINS a second rendering fails the local gate instead of shipping.
//
// It is test-only — no app module imports it, so it never reaches a bundle.
//
// HOW TO ADD A TERM: put the English label and its single canonical Chinese
// rendering in `GLOSSARY`. The test then requires every catalog key whose
// English value is that label to use exactly that Chinese value.
//
// HOW TO ADD AN EXCEPTION: only when one English word genuinely names two
// DIFFERENT things (see `SENSE_EXCEPTIONS`). Each entry carries the reason, the
// test rejects an exception that is no longer diverging, and review should push
// back on any entry that is really just a synonym someone liked better.
import type { TranslationKey } from "./catalog";

export interface GlossaryTerm {
  /** The exact English catalog value this term governs. */
  en: string;
  /** The single canonical Simplified Chinese rendering. */
  zh: string;
  /** Why this rendering, when the choice is not obvious. */
  note?: string;
}

/**
 * The control-plane vocabulary #348 enumerates: tenant/project/workspace,
 * provider/model, policy/guardrail, tokens/cost, MCP, agent run, worker, asset,
 * and deployment/revision terms — plus the cross-cutting table words that appear
 * on nearly every surface.
 */
export const GLOSSARY: readonly GlossaryTerm[] = [
  // --- Tenancy ---
  { en: "Tenant", zh: "租户" },
  { en: "Tenants", zh: "租户" },
  { en: "Project", zh: "项目" },
  { en: "Projects", zh: "项目" },
  {
    en: "Workspace",
    zh: "工作空间",
    note: "NOT 工作区 (which reads as a UI pane); a workspace is a tenancy object.",
  },
  { en: "Workspaces", zh: "工作空间" },
  { en: "Plan", zh: "套餐" },
  { en: "Plans", zh: "套餐" },
  { en: "Role", zh: "角色" },
  { en: "Roles", zh: "角色" },
  { en: "Permissions", zh: "权限" },
  { en: "API key", zh: "API 密钥" },
  { en: "API keys", zh: "API 密钥" },

  // --- Routing / providers ---
  {
    en: "Provider",
    zh: "提供商",
    note: "NOT 提供方; 提供商 is the vendor sense used by the provider registry.",
  },
  { en: "Providers", zh: "提供商" },
  { en: "Model", zh: "模型" },
  { en: "Models", zh: "模型" },
  { en: "Request logs", zh: "请求日志" },
  { en: "Audit events", zh: "审计事件" },

  // --- Policy / guardrails ---
  { en: "Policy", zh: "策略" },
  { en: "Guardrail policies", zh: "护栏策略" },
  { en: "Decision", zh: "决策" },
  { en: "Decision reason", zh: "决策原因" },
  { en: "Verdict", zh: "判定" },
  { en: "Action fingerprint", zh: "操作指纹" },

  // --- Usage / billing ---
  { en: "Tokens", zh: "令牌数" },
  { en: "Cost (USD)", zh: "费用（美元）" },
  { en: "Wallets", zh: "钱包" },
  { en: "Monthly budget (USD)", zh: "每月预算（美元）" },
  { en: "RPM limit", zh: "RPM 上限" },
  { en: "TPM limit", zh: "TPM 上限" },
  { en: "Model allowlist", zh: "模型允许列表" },

  // --- Agents / MCP / workers / assets ---
  {
    en: "Agent runs",
    zh: "智能体运行",
    note: "'agent' is 智能体 throughout; 代理 is reserved for PROXY (as in 代理请求).",
  },
  { en: "Agent run", zh: "智能体运行" },
  { en: "Agent run ID", zh: "智能体运行 ID" },
  { en: "MCP servers", zh: "MCP 服务器" },
  { en: "Assets", zh: "资产" },
  { en: "Site domains", zh: "站点域名" },

  // --- Deployment / revisions / operations ---
  {
    en: "Revision",
    zh: "修订版本",
    note: "A config/policy revision; 修订 alone reads as the verb 'to revise'.",
  },
  { en: "Active revision", zh: "生效修订版本" },
  { en: "Health", zh: "健康状态" },
  { en: "Enabled", zh: "已启用" },
  { en: "Disabled", zh: "已禁用" },

  // --- Cross-cutting table vocabulary ---
  { en: "Name", zh: "名称" },
  { en: "Description", zh: "描述" },
  { en: "Status", zh: "状态" },
  { en: "Kind", zh: "类型" },
  { en: "Action", zh: "操作" },
  { en: "Created", zh: "创建时间" },
  { en: "Updated", zh: "更新时间" },
  { en: "Request id", zh: "请求 ID" },
  { en: "Trace id", zh: "追踪 ID" },
];

/**
 * Keys where one English word names two genuinely DIFFERENT things, so a single
 * Chinese rendering would be wrong rather than merely inconsistent. Each entry
 * states which sense the key carries; `glossary.test.ts` fails if an entry stops
 * diverging (a stale exception is deleted, not left to rot) or carries no reason.
 *
 * This list is short ON PURPOSE. "I prefer this synonym" is not a sense
 * difference — unify instead.
 */
export const SENSE_EXCEPTIONS: Readonly<Partial<Record<TranslationKey, string>>> = {
  // "Active" — four different senses across four domains.
  "resource.promptTemplates.option.status.active":
    "Template LIFECYCLE status (Draft / Active / Archived): 启用, not the 活跃 'lively' sense.",
  "page.staticSites.history.active":
    "The version currently SERVED for the site — 当前生效, not liveness.",
  "page.assets.state.active":
    "Asset row STATE opposite 已撤回/withheld — 有效 (valid), not liveness.",

  // "Key" — an API key vs a map key.
  "resource.quotaPolicies.option.scopeType.key":
    "Quota scope 'key' means an API KEY (密钥); the sibling scopes are tenant/project/workspace.",

  // "Published" — a boolean state vs a timestamp.
  "resource.announcements.col.enabled":
    "Announcement PUBLISHED flag — boolean 已发布; staticSites 'Published' is a publish TIMESTAMP (发布时间).",
  "resource.announcements.field.enabled":
    "Announcement PUBLISHED flag — boolean 已发布; staticSites 'Published' is a publish TIMESTAMP (发布时间).",

  // "Latest" / "Versions" / "Total" — count vs referent.
  "page.assets.col.latest":
    "Column shows the latest VERSION string (最新版本); the worker card shows the latest TIMESTAMP.",
  "page.assets.col.versions":
    "Column is a COUNT of versions (版本数); the detail pane lists the versions themselves.",
  "page.billingMetering.col.total":
    "A monetary SUM (合计); the dashboard inventory 'Total' is a row COUNT (总数).",
};

/** Longest English label (in words) the consistency sweep treats as a term. */
export const MAX_TERM_WORDS = 3;
