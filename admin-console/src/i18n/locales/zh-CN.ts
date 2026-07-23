// Simplified Chinese (zh-CN) message catalog.
//
// Typed `Messages` (= `Record<TranslationKey, string>`), so this object MUST
// contain exactly the keys defined in `./en.ts`:
//   * a missing key  -> "property '...' is missing" type error;
//   * a misspelled / stale key -> excess-property type error.
// That is the compile-time half of the catalog-consistency guarantee; the
// runtime half lives in `../catalog.test.ts`.
//
// Autonyms (each language's name in its own script) are intentionally NOT
// translation keys — they live in `LOCALE_META` (`../catalog.ts`) so the
// selector always shows a language in its own name regardless of active locale.
import type { Messages } from "../catalog";

export const zhCN: Messages = {
  "language.label": "语言",
  "language.change": "切换语言",
  "language.current": "当前语言：{name}。切换语言",

  "common.appName": "FerroGate 管理控制台",
  "common.selected": "已选择 {count} 项",

  "common.status": "状态",
  "common.checking": "检查中",
  "common.unknown": "未知",
  "common.noData": "暂无数据",
  "common.pending": "待处理",
  "common.unableToLoad": "加载失败：{message}",

  "auth.field.email": "邮箱",
  "auth.field.password": "密码",
  "auth.login.subtitle": "登录以管理你的工作空间",
  "auth.login.submit": "登录",
  "auth.login.submitting": "正在登录…",
  "auth.login.error": "登录失败",
  "auth.login.registerPrompt": "还没有组织？",
  "auth.login.registerLink": "注册",
  "auth.register.title": "创建你的组织",
  "auth.register.subtitle": "创建一个以你为所有者的新租户",
  "auth.register.orgName": "组织名称",
  "auth.register.displayName": "你的名字（可选）",
  "auth.register.submit": "创建组织",
  "auth.register.submitting": "正在创建…",
  "auth.register.error": "注册失败",
  "auth.register.loginPrompt": "已经有账号了？",
  "auth.register.loginLink": "登录",

  "dashboard.title": "运维概览",
  "dashboard.subtitle": "{name} 的实时网关状态与运维操作。",
  "dashboard.updatedAt": "更新于 {time}",
  "dashboard.waitingForData": "等待数据",
  "dashboard.posture.title": "网关态势",
  "dashboard.posture.description": "独立实时检查；未知数据绝不视为健康。",
  "dashboard.metric.gatewayState": "网关状态",
  "dashboard.state.ready": "就绪",
  "dashboard.state.attention": "需关注",
  "dashboard.metric.snapshot": "快照 {snapshot}",
  "dashboard.metric.statusEndpoint": "状态端点",
  "dashboard.metric.providerHealth": "提供商健康",
  "dashboard.metric.healthyEnabled": "健康 / 已启用",
  "dashboard.metric.pendingApprovals": "待审批",
  "dashboard.metric.humanReview": "需人工审核",
  "dashboard.metric.recentRequests": "近期请求",
  "dashboard.metric.requestsUnavailable": "请求日志不可用",
  "dashboard.metric.failuresInLatest": "最近 {count} 条中有 {failures} 条失败",
  "dashboard.metric.latestCost": "最新费用",
  "dashboard.metric.usageReport": "用量报告",
  "dashboard.attention.title": "需要关注",
  "dashboard.attention.active": "{count} 项活跃",
  "dashboard.attention.empty": "没有活跃的网关、提供商或审批告警。",
  "dashboard.alert.statusError": "状态检查失败，网关就绪情况未知。",
  "dashboard.alert.clusterNotReady": "网关未就绪：{reason}。",
  "dashboard.alert.providersError": "提供商健康不可用：{message}。",
  "dashboard.alert.providersUnhealthy.one": "1 个提供商需要关注。",
  "dashboard.alert.providersUnhealthy.other": "{count} 个提供商需要关注。",
  "dashboard.alert.approvalsError": "无法检查待审批项：{message}。",
  "dashboard.alert.approvalsPending.one": "1 项工具审批等待审核。",
  "dashboard.alert.approvalsPending.other": "{count} 项工具审批等待审核。",
  "dashboard.requests.title": "近期请求",
  "dashboard.requests.description": "最近保留的网关流量与失败。",
  "dashboard.requests.viewLogs": "查看日志",
  "dashboard.requests.colRequest": "请求",
  "dashboard.requests.colProviderModel": "提供商 / 模型",
  "dashboard.requests.colStarted": "开始时间",
  "dashboard.requests.loading": "正在加载近期请求…",
  "dashboard.requests.empty": "暂无保留的请求。",
  "dashboard.requests.unmappedModel": "未映射的模型",
  "dashboard.usage.title": "用量与费用",
  "dashboard.usage.description": "最新的租户优先用量汇总。",
  "dashboard.usage.viewReports": "查看报告",
  "dashboard.usage.loading": "正在加载用量报告…",
  "dashboard.usage.empty": "暂无可用的用量报告。",
  "dashboard.usage.cost": "费用",
  "dashboard.usage.requests": "请求数",
  "dashboard.usage.tokens": "令牌数",
  "dashboard.usage.errors": "错误数",
  "dashboard.usage.period": "周期",
  "dashboard.usage.latest": "最新",
};
