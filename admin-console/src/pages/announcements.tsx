import { CatalogScopeToggle } from "@/components/resource/catalog-scope-toggle";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useCatalogApiKey } from "@/hooks/use-catalog-api-key";
import { useCatalogScope } from "@/hooks/use-catalog-scope";
import { useOperatorError } from "@/hooks/use-operator-error";
import { useI18n } from "@/i18n";
import { adminDelete, adminGet, adminPatch, adminPost } from "@/lib/gateway-client";
import {
  ANNOUNCEMENT_LEVELS,
  type AdminAnnouncement as Announcement,
  type AnnouncementMutation,
} from "@/resources/announcements";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { toast } from "sonner";

// Platform announcements console surface (公告, #948 — the shared-config channel's
// second domain). The operator UI over GET/POST /admin/v1/announcements and
// GET/PATCH/DELETE /admin/v1/announcements/{id}. An announcement carries a title,
// a body, a display `level`, a published flag and an optional [starts, ends]
// display window; the one-way fan-out mirrors it read-only into every tenant DO.
//
// This REUSES the platform-scope machinery (`useCatalogApiKey()` +
// `<CatalogScopeToggle>`) exactly as billing-groups.tsx: the surface is
// platform-operator ONLY — a tenant-scoped caller is fenced with a leak-proof
// 404 — so the operator flips to platform scope to reach it. The console never
// sends a `tenant_id`; scope is resolved purely from WHICH credential asked.

interface AnnouncementFormState {
  title: string;
  body: string;
  level: string;
  enabled: boolean;
  startsAt: string;
  endsAt: string;
}

/** unix seconds -> the `YYYY-MM-DDTHH:mm` a `datetime-local` input wants, in LOCAL time. */
function unixToLocalInput(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "";
  const date = new Date(unix * 1000);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

/** A `datetime-local` value back to unix seconds; blank -> null (unbounded end). */
function localInputToUnix(value: string): number | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  const ms = new Date(trimmed).getTime();
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / 1000);
}

function emptyForm(): AnnouncementFormState {
  return { title: "", body: "", level: "info", enabled: true, startsAt: "", endsAt: "" };
}

function formFromAnnouncement(announcement: Announcement): AnnouncementFormState {
  return {
    title: announcement.title,
    body: announcement.body,
    level: announcement.level,
    enabled: announcement.enabled,
    startsAt: unixToLocalInput(announcement.starts_at_unix),
    endsAt: unixToLocalInput(announcement.ends_at_unix),
  };
}

export default function AnnouncementsPage() {
  const { t } = useI18n();
  const { toastError } = useOperatorError();
  // The credential follows the active scope; the list query keys on it so
  // flipping the toggle refetches the platform surface.
  const apiKey = useCatalogApiKey();
  const { scope } = useCatalogScope();
  const queryClient = useQueryClient();
  const announcementsKey = useMemo(() => ["announcements", scope], [scope]);

  const [formOpen, setFormOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<AnnouncementFormState>(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Announcement | null>(null);

  const {
    data: listData,
    isLoading,
    error: listError,
  } = useQuery({
    queryKey: announcementsKey,
    queryFn: () => adminGet(apiKey, "/admin/v1/announcements"),
  });

  const announcements = useMemo<Announcement[]>(() => listData?.data ?? [], [listData]);

  const editing = useMemo(
    () => (editingId ? (announcements.find((item) => item.id === editingId) ?? null) : null),
    [editingId, announcements],
  );

  function openCreate() {
    setEditingId(null);
    setForm(emptyForm());
    setFormError(null);
    setFormOpen(true);
  }

  function openEdit(announcement: Announcement) {
    setEditingId(announcement.id);
    setForm(formFromAnnouncement(announcement));
    setFormError(null);
    setFormOpen(true);
  }

  const createMutation = useMutation({
    mutationFn: (body: AnnouncementMutation) => adminPost(apiKey, "/admin/v1/announcements", body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: announcementsKey });
      toast.success(t("page.announcements.toast.created"));
      setFormOpen(false);
      setEditingId(null);
    },
    onError: (error: Error) => {
      setFormError(error.message);
      toastError(error);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: AnnouncementMutation }) =>
      adminPatch(apiKey, "/admin/v1/announcements/{id}", body, { params: { id } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: announcementsKey });
      toast.success(t("page.announcements.toast.updated"));
      setFormOpen(false);
      setEditingId(null);
    },
    onError: (error: Error) => {
      setFormError(error.message);
      toastError(error);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      adminDelete(apiKey, "/admin/v1/announcements/{id}", { params: { id } }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: announcementsKey });
      toast.success(t("page.announcements.toast.deleted"));
      setDeleting(null);
    },
    onError: (error: Error) => {
      toastError(error);
      setDeleting(null);
    },
  });

  function submitForm() {
    setFormError(null);
    const title = form.title.trim();
    if (title === "") {
      setFormError(t("page.announcements.validation.titleRequired"));
      return;
    }
    const body = form.body.trim();
    if (body === "") {
      setFormError(t("page.announcements.validation.bodyRequired"));
      return;
    }
    const startsAtUnix = localInputToUnix(form.startsAt);
    const endsAtUnix = localInputToUnix(form.endsAt);
    if (startsAtUnix !== null && endsAtUnix !== null && startsAtUnix > endsAtUnix) {
      setFormError(t("page.announcements.validation.windowInvalid"));
      return;
    }
    const level = form.level.trim();
    const payload: AnnouncementMutation = {
      title,
      body,
      level: level === "" ? "info" : level,
      enabled: form.enabled,
      starts_at_unix: startsAtUnix,
      ends_at_unix: endsAtUnix,
    };
    if (editing) {
      updateMutation.mutate({ id: editing.id, body: payload });
    } else {
      createMutation.mutate(payload);
    }
  }

  const submitting = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">{t("resource.announcements.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("resource.announcements.description")}</p>
          {scope === "platform" ? (
            <p className="mt-1 text-xs text-muted-foreground">{t("catalog.scope.hint")}</p>
          ) : (
            <p className="mt-1 text-xs text-muted-foreground">
              {t("page.announcements.platformHint")}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <CatalogScopeToggle />
          <Button onClick={openCreate}>{t("resource.action.new")}</Button>
        </div>
      </div>

      {listError ? (
        <p
          role="alert"
          className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {t("page.announcements.loadError", { message: listError.message })}
        </p>
      ) : null}

      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("resource.announcements.col.title")}</TableHead>
              <TableHead>{t("resource.announcements.col.level")}</TableHead>
              <TableHead>{t("resource.announcements.col.enabled")}</TableHead>
              <TableHead className="w-32">
                <span className="sr-only">{t("resource.table.actionsColumn")}</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={4} className="h-24 text-center">
                  {t("resource.table.loading")}
                </TableCell>
              </TableRow>
            ) : announcements.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="h-24 text-center">
                  {t("page.announcements.empty")}
                </TableCell>
              </TableRow>
            ) : (
              announcements.map((announcement) => (
                <TableRow key={announcement.id} data-testid={`announcement-${announcement.id}`}>
                  <TableCell className="font-medium">{announcement.title}</TableCell>
                  <TableCell>{announcement.level}</TableCell>
                  <TableCell>{announcement.enabled ? t("common.yes") : t("common.no")}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => openEdit(announcement)}>
                        {t("resource.action.edit")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        onClick={() => setDeleting(announcement)}
                      >
                        {t("resource.action.delete")}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Sheet open={formOpen} onOpenChange={setFormOpen}>
        <SheetContent className="overflow-y-auto sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>
              {editing ? t("page.announcements.edit.title") : t("page.announcements.create.title")}
            </SheetTitle>
          </SheetHeader>
          <div className="grid gap-3 px-4 pb-4">
            <div className="grid gap-1.5">
              <Label htmlFor="title">{t("resource.announcements.field.title")} *</Label>
              <Input
                id="title"
                value={form.title}
                onChange={(event) => setForm((prev) => ({ ...prev, title: event.target.value }))}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="body">{t("resource.announcements.field.body")} *</Label>
              <Textarea
                id="body"
                value={form.body}
                onChange={(event) => setForm((prev) => ({ ...prev, body: event.target.value }))}
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="level">{t("resource.announcements.field.level")}</Label>
              <Input
                id="level"
                list="announcement-levels"
                value={form.level}
                onChange={(event) => setForm((prev) => ({ ...prev, level: event.target.value }))}
              />
              <datalist id="announcement-levels">
                {ANNOUNCEMENT_LEVELS.map((level) => (
                  <option key={level} value={level} />
                ))}
              </datalist>
              <p className="text-xs text-muted-foreground">
                {t("page.announcements.field.level.hint")}
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="startsAt">{t("resource.announcements.field.startsAt")}</Label>
                <Input
                  id="startsAt"
                  type="datetime-local"
                  value={form.startsAt}
                  onChange={(event) =>
                    setForm((prev) => ({ ...prev, startsAt: event.target.value }))
                  }
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="endsAt">{t("resource.announcements.field.endsAt")}</Label>
                <Input
                  id="endsAt"
                  type="datetime-local"
                  value={form.endsAt}
                  onChange={(event) => setForm((prev) => ({ ...prev, endsAt: event.target.value }))}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              {t("page.announcements.field.window.hint")}
            </p>
            <div className="flex items-center gap-2">
              <Switch
                id="enabled"
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((prev) => ({ ...prev, enabled: checked }))}
              />
              <Label htmlFor="enabled">{t("resource.announcements.field.enabled")}</Label>
            </div>

            {formError ? (
              <p
                role="alert"
                className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                {formError}
              </p>
            ) : null}

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => setFormOpen(false)}>
                {t("resource.action.cancel")}
              </Button>
              <Button onClick={submitForm} disabled={submitting}>
                {editing ? t("resource.action.saveChanges") : t("resource.action.create")}
              </Button>
            </div>
          </div>
        </SheetContent>
      </Sheet>

      <AlertDialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("page.announcements.delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("page.announcements.delete.description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("resource.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                if (deleting) deleteMutation.mutate(deleting.id);
              }}
            >
              {t("resource.action.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
