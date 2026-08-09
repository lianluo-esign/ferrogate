import { useRef, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { AsyncStatus } from "@/components/ui/async-status";
import { MoreHorizontal } from "lucide-react";
import { TruncatedCopyable } from "@/components/agent-ops/agent-ops-primitives";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useMediaQuery } from "@/hooks/use-media-query";
import { useI18n } from "@/i18n";
import {
  resolveConfigText,
  type ColumnConfig,
  type ResourceTranslator,
} from "@/lib/resource-config";

interface ResourceTableProps<T extends Record<string, unknown>> {
  columns: ColumnConfig<T>[];
  rows: T[];
  isLoading: boolean;
  readOnly?: boolean;
  emptyLabel?: string;
  rowLabel?: (row: T) => string;
  /** Row-nav (#912): when set, each row's FIRST column links to this target. */
  rowHref?: (row: T) => string;
  onEdit?: (row: T, trigger?: HTMLElement | null) => void;
  onDelete?: (row: T, trigger?: HTMLElement | null) => void;
  renderActions?: (row: T) => ReactNode;
}

function rawColumnValue<T>(column: ColumnConfig<T>, row: T): string {
  const value = (row as Record<string, unknown>)[column.key];
  if (Array.isArray(value)) return value.join(", ");
  return String(value ?? "-");
}

function columnValue<T>(
  column: ColumnConfig<T>,
  row: T,
  compact: boolean,
  header: string,
  t: ResourceTranslator,
): ReactNode {
  if (column.copyable) {
    return <TruncatedCopyable value={rawColumnValue(column, row)} label={header} />;
  }
  const renderer = compact ? column.compactRender ?? column.render : column.render;
  // Render callbacks receive the active translator so cell-derived copy
  // (boolean Yes/No, Enabled/Disabled, …) localizes with the table (#385).
  return renderer ? renderer(row, t) : rawColumnValue(column, row);
}

function RowActions<T extends Record<string, unknown>>({
  row,
  label,
  onEdit,
  onDelete,
  renderActions,
}: {
  row: T;
  label: string;
  onEdit?: (row: T, trigger?: HTMLElement | null) => void;
  onDelete?: (row: T, trigger?: HTMLElement | null) => void;
  renderActions?: (row: T) => ReactNode;
}) {
  const { t } = useI18n();
  const triggerRef = useRef<HTMLButtonElement>(null);
  if (renderActions) return <>{renderActions(row)}</>;
  if (!onEdit && !onDelete) return null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          ref={triggerRef}
          variant="ghost"
          size="icon"
          className="size-11 lg:size-8"
          aria-label={t("resource.action.rowActions", { label })}
        >
          <MoreHorizontal className="size-4" aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {onEdit ? (
          <DropdownMenuItem onSelect={() => onEdit(row, triggerRef.current)}>{t("resource.action.edit")}</DropdownMenuItem>
        ) : null}
        {onDelete ? (
          <DropdownMenuItem className="text-destructive" onSelect={() => onDelete(row, triggerRef.current)}>
            {t("resource.action.delete")}
          </DropdownMenuItem>
        ) : null}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function ResourceTable<T extends Record<string, unknown>>({
  columns,
  rows,
  isLoading,
  readOnly,
  emptyLabel,
  rowLabel,
  rowHref,
  onEdit,
  onDelete,
  renderActions,
}: ResourceTableProps<T>) {
  const { t } = useI18n();
  const isDesktop = useMediaQuery("(min-width: 1024px)");
  const hasActions = !readOnly && Boolean(onEdit || onDelete || renderActions);
  const labelFor = (row: T) => rowLabel?.(row) ?? rawColumnValue(columns[0], row);
  // Row-nav (#912): the first column links to `rowHref(row)` when provided,
  // otherwise renders its plain value. Applied to both the desktop table and the
  // compact record view so a row is navigable at every breakpoint.
  const linkWrap = (content: ReactNode, row: T): ReactNode =>
    rowHref ? (
      <Link to={rowHref(row)} className="font-medium text-primary hover:underline">
        {content}
      </Link>
    ) : (
      content
    );
  // Column headers prefer the typed catalog key (migrated resources) and fall
  // back to the legacy inline literal for resources not yet migrated (#348).
  const headerFor = (column: ColumnConfig<T>) =>
    resolveConfigText(t, column.headerKey, column.header);
  const resolvedEmptyLabel = emptyLabel ?? t("resource.table.empty");

  if (!isDesktop) {
    if (isLoading) {
      return (
        <div className="flex min-h-24 items-center justify-center rounded-md border">
          <AsyncStatus>{t("resource.table.loading")}</AsyncStatus>
        </div>
      );
    }
    if (rows.length === 0) {
      return (
        <div className="flex min-h-24 items-center justify-center rounded-md border text-sm text-muted-foreground">
          {resolvedEmptyLabel}
        </div>
      );
    }

    return (
      <div className="grid gap-3" data-compact-records>
        {rows.map((row, rowIndex) => {
          const summaryColumns = columns.filter((column, columnIndex) => {
            if (column.mobileVisibility === "hidden") return false;
            if (column.mobileVisibility === "always") return true;
            if (column.mobileVisibility === "details") return false;
            return column.priority === "primary" || columnIndex < 2;
          });
          const detailColumns = columns.filter(
            (column) =>
              column.mobileVisibility !== "hidden" && !summaryColumns.includes(column),
          );
          const label = labelFor(row);
          return (
            <article key={`${label}-${rowIndex}`} className="rounded-md border px-3 py-2">
              <dl className="divide-y">
                {summaryColumns.map((column, columnIndex) => (
                  <div key={column.key} className="grid grid-cols-[minmax(6rem,0.8fr)_minmax(0,1.4fr)] gap-3 py-2">
                    <dt className="text-xs font-medium text-muted-foreground">{headerFor(column)}</dt>
                    <dd className="min-w-0 break-words text-sm">
                      {columnIndex === 0
                        ? linkWrap(columnValue(column, row, true, headerFor(column), t), row)
                        : columnValue(column, row, true, headerFor(column), t)}
                    </dd>
                  </div>
                ))}
              </dl>
              {detailColumns.length > 0 ? (
                <details className="border-t">
                  <summary className="flex min-h-11 cursor-pointer items-center text-sm font-medium">
                    {t("resource.table.moreDetails")}
                  </summary>
                  <dl className="divide-y border-t">
                    {detailColumns.map((column) => (
                      <div key={column.key} className="grid grid-cols-[minmax(6rem,0.8fr)_minmax(0,1.4fr)] gap-3 py-2">
                        <dt className="text-xs font-medium text-muted-foreground">{headerFor(column)}</dt>
                        <dd className="min-w-0 break-words text-sm">{columnValue(column, row, true, headerFor(column), t)}</dd>
                      </div>
                    ))}
                  </dl>
                </details>
              ) : null}
              {hasActions ? (
                <div className="flex min-h-11 items-center justify-end gap-2 border-t pt-2">
                  <RowActions
                    row={row}
                    label={label}
                    onEdit={onEdit}
                    onDelete={onDelete}
                    renderActions={renderActions}
                  />
                </div>
              ) : null}
            </article>
          );
        })}
      </div>
    );
  }

  const colSpan = columns.length + (hasActions ? 1 : 0);
  return (
    <div className="overflow-x-auto rounded-md border">
      <Table className="table-fixed">
        <TableHeader>
          <TableRow>
            {columns.map((column) => (
              <TableHead key={column.key} style={{ minWidth: column.minWidth, width: column.minWidth }}>
                {headerFor(column)}
              </TableHead>
            ))}
            {hasActions ? <TableHead className="w-14"><span className="sr-only">{t("resource.table.actionsColumn")}</span></TableHead> : null}
          </TableRow>
        </TableHeader>
        <TableBody>
          {isLoading ? (
            <TableRow>
              <TableCell colSpan={colSpan} className="h-24 text-center">
                <AsyncStatus>{t("resource.table.loading")}</AsyncStatus>
              </TableCell>
            </TableRow>
          ) : rows.length === 0 ? (
            <TableRow>
              <TableCell colSpan={colSpan} className="h-24 text-center">{resolvedEmptyLabel}</TableCell>
            </TableRow>
          ) : (
            rows.map((row, rowIndex) => {
              const label = labelFor(row);
              return (
                <TableRow key={`${label}-${rowIndex}`}>
                  {columns.map((column, columnIndex) => (
                    <TableCell key={column.key} className="min-w-0 overflow-hidden">
                      {columnIndex === 0
                        ? linkWrap(columnValue(column, row, false, headerFor(column), t), row)
                        : columnValue(column, row, false, headerFor(column), t)}
                    </TableCell>
                  ))}
                  {hasActions ? (
                    <TableCell className="text-right">
                      <RowActions
                        row={row}
                        label={label}
                        onEdit={onEdit}
                        onDelete={onDelete}
                        renderActions={renderActions}
                      />
                    </TableCell>
                  ) : null}
                </TableRow>
              );
            })
          )}
        </TableBody>
      </Table>
    </div>
  );
}
