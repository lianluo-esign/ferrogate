import type { TranslationKey } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";

/**
 * Platform announcement resource definition (公告, #948 — the shared-config
 * channel's second domain after billing groups).
 *
 * An operator authors a notice ONCE here, on the control database, over
 * GET/POST /admin/v1/announcements and GET/PATCH/DELETE /admin/v1/announcements/{id}.
 * The one-way shared-config fan-out then mirrors it READ-ONLY into every
 * tenant's own Durable Object (`shared_announcements`), so a tenant renders the
 * notice from its own object with no control-plane hop.
 *
 * Like `billing-groups.ts` this is NOT a generic `ResourceConfig` in
 * `RESOURCE_ROUTES`: the create/patch contract (`AnnouncementMutation`) is
 * `additionalProperties:false` and the surface is `platformScopable` — the
 * endpoints are platform-operator ONLY (a tenant-scoped caller is fenced with a
 * leak-proof 404), so the bespoke page (`src/pages/announcements.tsx`) addresses
 * it under the shared #912 catalog-scope machinery and consumes this module as
 * the single source of truth for the base path, the typed row shape and copy.
 */
export type AdminAnnouncement = AdminSchema<"Announcement">;
export type AnnouncementMutation = AdminSchema<"AnnouncementMutation">;

export const ANNOUNCEMENTS_BASE_PATH = "/admin/v1/announcements";

export interface AnnouncementColumn {
  key: keyof AdminAnnouncement & string;
  headerKey: TranslationKey;
}

export interface AnnouncementField {
  name: "title" | "body" | "level" | "enabled" | "starts_at_unix" | "ends_at_unix";
  labelKey: TranslationKey;
  type: "text" | "textarea" | "boolean" | "datetime";
  required?: boolean;
}

/**
 * The display-severity values the tenant UI maps to a colour/icon. The backend
 * accepts free text with an `info` default, so this list is only the console's
 * suggested set; an unknown value falls to the neutral treatment client-side.
 */
export const ANNOUNCEMENT_LEVELS = ["info", "warning", "critical"] as const;
export type AnnouncementLevel = (typeof ANNOUNCEMENT_LEVELS)[number];

export const announcementsResource = {
  key: "announcements",
  titleKey: "resource.announcements.title",
  descriptionKey: "resource.announcements.description",
  basePath: ANNOUNCEMENTS_BASE_PATH,
  idField: "id",
  platformScopable: true,
  columns: [
    { key: "title", headerKey: "resource.announcements.col.title" },
    { key: "level", headerKey: "resource.announcements.col.level" },
    { key: "enabled", headerKey: "resource.announcements.col.enabled" },
  ] satisfies AnnouncementColumn[],
  fields: [
    { name: "title", labelKey: "resource.announcements.field.title", type: "text", required: true },
    {
      name: "body",
      labelKey: "resource.announcements.field.body",
      type: "textarea",
      required: true,
    },
    { name: "level", labelKey: "resource.announcements.field.level", type: "text" },
    { name: "enabled", labelKey: "resource.announcements.field.enabled", type: "boolean" },
    { name: "starts_at_unix", labelKey: "resource.announcements.field.startsAt", type: "datetime" },
    { name: "ends_at_unix", labelKey: "resource.announcements.field.endsAt", type: "datetime" },
  ] satisfies AnnouncementField[],
} as const;
