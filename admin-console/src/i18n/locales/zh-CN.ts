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
};
