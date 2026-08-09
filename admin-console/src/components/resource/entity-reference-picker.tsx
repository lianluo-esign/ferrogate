import { AsyncStatus } from "@/components/ui/async-status";
import { Badge, badgeVariants } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/use-auth";
import { useI18n } from "@/i18n";
import {
  type EntityReferenceOption,
  hydrateEntityReference,
  loadEntityReferencePage,
} from "@/lib/entity-reference-registry";
import type { EntityReferenceConfig } from "@/lib/resource-config";
import { cn } from "@/lib/utils";
import { keepPreviousData, useInfiniteQuery, useQueries } from "@tanstack/react-query";
import { Check, ChevronsUpDown, Copy, LoaderCircle, Search, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

interface EntityReferencePickerProps {
  id: string;
  label: string;
  reference: EntityReferenceConfig;
  value: unknown;
  dependencyValues: Record<string, unknown>;
  multiple?: boolean;
  required?: boolean;
  placeholder?: string;
  onChange: (value: string | string[]) => void;
}

function useDebouncedValue(value: string, delayMs: number): string {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timeout = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(timeout);
  }, [delayMs, value]);

  return debounced;
}

function normalizedValues(value: unknown, multiple: boolean): string[] {
  if (multiple) {
    return Array.isArray(value)
      ? [
          ...new Set(
            value
              .map(String)
              .map((item) => item.trim())
              .filter(Boolean),
          ),
        ]
      : [];
  }
  const single = typeof value === "string" ? value.trim() : "";
  return single ? [single] : [];
}

/**
 * Arrow-key traversal skips disabled options (#340): a disabled `<button>` is
 * not focusable, so including it in the walk would stall the keyboard at the
 * first suspended row.
 */
function moveOptionFocus(container: HTMLElement | null, current: HTMLElement, delta: number) {
  const options = Array.from(
    container?.querySelectorAll<HTMLElement>("[role='option']:not([disabled])") ?? [],
  );
  const index = options.indexOf(current);
  options[index + delta]?.focus();
}

export function EntityReferencePicker({
  id,
  label,
  reference,
  value,
  dependencyValues,
  multiple = false,
  required,
  placeholder,
  onChange,
}: EntityReferencePickerProps) {
  const { session } = useAuth();
  const apiKey = (session as NonNullable<typeof session>).gatewayApiKey;
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search.trim(), 250);
  const listboxRef = useRef<HTMLDivElement>(null);
  const optionRefs = useRef(new Map<string, HTMLButtonElement>());
  const selectedValues = useMemo(() => normalizedValues(value, multiple), [multiple, value]);
  const selectedValuesRef = useRef(selectedValues);
  selectedValuesRef.current = selectedValues;
  const filters = useMemo(() => {
    const next: Record<string, string> = {};
    for (const dependency of reference.dependencies ?? []) {
      const dependencyValue = String(dependencyValues[dependency.field] ?? "").trim();
      if (dependencyValue) next[dependency.queryKey] = dependencyValue;
    }
    return next;
  }, [dependencyValues, reference.dependencies]);
  const missingDependency = (reference.dependencies ?? []).find(
    (dependency) => !String(dependencyValues[dependency.field] ?? "").trim(),
  );
  const filtersKey = JSON.stringify(filters);
  const referenceKey = JSON.stringify({
    target: reference.target,
    valueKey: reference.valueKey,
    primaryLabelKey: reference.primaryLabelKey,
    secondaryLabelKeys: reference.secondaryLabelKeys,
    queryKey: reference.queryKey,
    offsetKey: reference.offsetKey,
    limitKey: reference.limitKey,
    pageSize: reference.pageSize,
    disabledWhen: reference.disabledWhen,
  });

  const selectedQueries = useQueries({
    queries: selectedValues.map((selectedValue) => ({
      queryKey: ["entity-reference", "hydrate", referenceKey, filtersKey, selectedValue],
      queryFn: ({ signal }) =>
        hydrateEntityReference(apiKey, reference, selectedValue, filters, signal),
      staleTime: 60_000,
    })),
  });

  const listQuery = useInfiniteQuery({
    queryKey: ["entity-reference", "list", referenceKey, filtersKey, debouncedSearch],
    queryFn: ({ pageParam, signal }) =>
      loadEntityReferencePage(apiKey, reference, {
        search: debouncedSearch,
        offset: pageParam,
        filters,
        signal,
      }),
    initialPageParam: 0,
    getNextPageParam: (lastPage) => lastPage.nextOffset,
    placeholderData: keepPreviousData,
    enabled: open && !missingDependency,
    staleTime: 30_000,
  });

  const optionsByValue = useMemo(() => {
    const unique = new Map<string, EntityReferenceOption>();
    for (const page of listQuery.data?.pages ?? []) {
      for (const option of page.options) unique.set(option.value, option);
    }
    return unique;
  }, [listQuery.data?.pages]);
  const options = useMemo(() => [...optionsByValue.values()], [optionsByValue]);
  const optionsRef = useRef(optionsByValue);
  optionsRef.current = optionsByValue;

  const selectedOptions = selectedValues.map((selectedValue, index) => {
    const query = selectedQueries[index];
    if (query.data) return query.data;
    return {
      value: selectedValue,
      primaryLabel: selectedValue,
      unresolved: !query.isPending && !query.error,
      resolutionError: Boolean(query.error),
    } satisfies EntityReferenceOption;
  });

  function selectOption(optionValue: string) {
    // #340 box 5: the listed option is already `disabled`, so this only guards
    // programmatic callers (and any future non-button trigger) from newly
    // selecting a suspended target.
    if (optionsRef.current.get(optionValue)?.disabled) return;
    if (!multiple) {
      selectedValuesRef.current = [optionValue];
      onChange(optionValue);
      setOpen(false);
      return;
    }
    const currentValues = selectedValuesRef.current;
    const nextValues = currentValues.includes(optionValue)
      ? currentValues.filter((selected) => selected !== optionValue)
      : [...currentValues, optionValue];
    selectedValuesRef.current = nextValues;
    onChange(nextValues);
  }

  function removeOption(optionValue: string) {
    const nextValue = multiple
      ? selectedValuesRef.current.filter((selected) => selected !== optionValue)
      : "";
    selectedValuesRef.current = Array.isArray(nextValue) ? nextValue : [];
    onChange(nextValue);
  }

  function restoreOptionFocus(optionValue: string) {
    window.requestAnimationFrame(() => optionRefs.current.get(optionValue)?.focus());
  }

  const listboxId = `${id}-options`;
  const dialogId = `${id}-picker`;
  const dependencyLabel = missingDependency
    ? (missingDependency.label ?? missingDependency.field.replaceAll("_", " "))
    : undefined;

  return (
    <div className="grid gap-2">
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTrigger asChild>
          <Button
            id={id}
            type="button"
            variant="outline"
            // biome-ignore lint/a11y/useSemanticElements: this is the trigger of a custom async-search combobox rendered in a dialog; a native <select> cannot host the styled popover, so the ARIA combobox role on the button is intentional
            role="combobox"
            aria-controls={dialogId}
            aria-expanded={open}
            aria-required={required}
            disabled={Boolean(missingDependency)}
            className="h-auto min-h-10 w-full justify-between gap-2 px-3 py-2 font-normal"
          >
            <span
              className={cn("truncate", selectedValues.length === 0 && "text-muted-foreground")}
            >
              {missingDependency
                ? t("resource.picker.selectDependencyFirst", { name: dependencyLabel ?? "" })
                : selectedValues.length === 0
                  ? (placeholder ??
                    t("resource.picker.selectPlaceholder", { label: label.toLowerCase() }))
                  : multiple
                    ? t("common.selected", { count: selectedValues.length })
                    : selectedOptions[0]?.primaryLabel}
            </span>
            <ChevronsUpDown className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          </Button>
        </DialogTrigger>
        <DialogContent
          id={dialogId}
          className="max-h-[min(42rem,calc(100vh-2rem))] w-[calc(100%-2rem)] gap-3 overflow-hidden p-4 sm:max-w-xl sm:p-6"
        >
          <DialogHeader>
            <DialogTitle>{t("resource.picker.dialogTitle", { label })}</DialogTitle>
            <DialogDescription className="sr-only">
              {t("resource.picker.dialogDescription", { label: label.toLowerCase() })}
            </DialogDescription>
          </DialogHeader>
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              autoFocus
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "ArrowDown") {
                  event.preventDefault();
                  listboxRef.current
                    ?.querySelector<HTMLElement>("[role='option']:not([disabled])")
                    ?.focus();
                }
              }}
              className="pl-9"
              placeholder={t("resource.picker.searchPlaceholder")}
              aria-label={t("resource.picker.searchLabel", { label })}
              aria-controls={listboxId}
            />
          </div>
          {/* biome-ignore lint/a11y/useFocusableInteractive: the listbox is a scroll container whose focusable children are the option buttons, so the container itself is deliberately not a tab stop */}
          <div
            ref={listboxRef}
            id={listboxId}
            // biome-ignore lint/a11y/useSemanticElements: a custom async-search listbox — a native <select> cannot render these richly-styled async option rows
            role="listbox"
            aria-label={t("resource.picker.optionsLabel", { label })}
            aria-multiselectable={multiple || undefined}
            className="min-h-40 flex-1 overflow-y-auto rounded-md border p-1"
          >
            {listQuery.isPending ? (
              <div
                className="flex min-h-40 items-center justify-center gap-2 text-sm text-muted-foreground"
                // biome-ignore lint/a11y/useSemanticElements: ARIA live region for async loading; the flex layout classes here assume a div, which <output>'s inline default would break
                role="status"
              >
                <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
                {t("resource.table.loading")}
              </div>
            ) : listQuery.error ? (
              <div className="grid gap-2 p-3">
                <AsyncStatus tone="error">
                  {t("resource.picker.loadError", { message: listQuery.error.message })}
                </AsyncStatus>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => listQuery.refetch()}
                >
                  {t("resource.action.retry")}
                </Button>
              </div>
            ) : options.length === 0 ? (
              <p
                className="flex min-h-40 items-center justify-center text-sm text-muted-foreground"
                // biome-ignore lint/a11y/useSemanticElements: ARIA live region for the empty-results message; the flex layout classes assume a block <p>, which <output>'s inline default would break
                role="status"
              >
                {t("resource.picker.noMatches")}
              </p>
            ) : (
              options.map((option) => {
                const selected = selectedValues.includes(option.value);
                return (
                  <button
                    key={option.value}
                    ref={(element) => {
                      if (element) optionRefs.current.set(option.value, element);
                      else optionRefs.current.delete(option.value);
                    }}
                    type="button"
                    // biome-ignore lint/a11y/useSemanticElements: an option row inside the custom listbox above; a native <option> cannot be a focusable, richly-styled button, so the ARIA option role is intentional
                    role="option"
                    aria-selected={selected}
                    // #340 box 5: a disabled/suspended target stays listed (so an
                    // operator can see why their id resolves to nothing) but
                    // cannot be newly selected. An already-stored value is still
                    // removable through its chip below.
                    disabled={option.disabled}
                    onClick={(event) => {
                      selectOption(option.value);
                      if (event.detail === 0) restoreOptionFocus(option.value);
                    }}
                    onKeyDown={(event) => {
                      if (event.key === "ArrowDown") {
                        event.preventDefault();
                        moveOptionFocus(listboxRef.current, event.currentTarget, 1);
                      } else if (event.key === "ArrowUp") {
                        event.preventDefault();
                        moveOptionFocus(listboxRef.current, event.currentTarget, -1);
                      }
                    }}
                    className="flex min-h-11 w-full items-center gap-3 rounded-sm px-3 py-2 text-left text-sm outline-none hover:bg-accent focus-visible:bg-accent focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:bg-transparent"
                  >
                    <Check
                      className={cn("size-4 shrink-0", selected ? "opacity-100" : "opacity-0")}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <span className="truncate font-medium">{option.primaryLabel}</span>
                        {/* A `<button>` may only contain phrasing content, so the
                            marker is a span carrying the Badge styling rather
                            than the Badge component (which renders a div). */}
                        {option.disabled ? (
                          <span className={cn(badgeVariants({ variant: "outline" }), "shrink-0")}>
                            {t("resource.picker.disabledReference")}
                          </span>
                        ) : null}
                      </span>
                      <span className="block truncate text-xs text-muted-foreground" translate="no">
                        {[option.secondaryLabel, option.value].filter(Boolean).join(" · ")}
                      </span>
                    </span>
                  </button>
                );
              })
            )}
          </div>
          {reference.allowRawValue &&
          search.trim() &&
          !options.some((option) => option.value === search.trim()) ? (
            <Button type="button" variant="outline" onClick={() => selectOption(search.trim())}>
              {t("resource.picker.useExactId")}{" "}
              <code className="ml-1 max-w-52 truncate" translate="no">
                {search.trim()}
              </code>
            </Button>
          ) : null}
          {listQuery.hasNextPage ? (
            <Button
              type="button"
              variant="outline"
              disabled={listQuery.isFetchingNextPage}
              onClick={() => listQuery.fetchNextPage()}
            >
              {listQuery.isFetchingNextPage
                ? t("resource.table.loading")
                : t("resource.action.loadMore")}
            </Button>
          ) : null}
        </DialogContent>
      </Dialog>

      {selectedOptions.length > 0 ? (
        <ul className="grid gap-1" aria-label={t("resource.picker.selectedLabel", { label })}>
          {selectedOptions.map((option) => (
            <li
              key={option.value}
              className="flex min-w-0 items-center gap-2 rounded-md border px-2 py-1.5 text-sm"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate font-medium">{option.primaryLabel}</span>
                  {option.resolutionError ? (
                    <Badge variant="outline">{t("resource.picker.resolutionUnavailable")}</Badge>
                  ) : option.unresolved ? (
                    <Badge variant="outline">{t("resource.picker.unresolvedReference")}</Badge>
                  ) : option.disabled ? (
                    // #340 box 5: a stored value whose target has since been
                    // disabled stays inspectable and repairable, marked the same
                    // way a deleted one is.
                    <Badge variant="outline">{t("resource.picker.disabledReference")}</Badge>
                  ) : null}
                </div>
                <code className="block truncate text-xs text-muted-foreground" translate="no">
                  {option.value}
                </code>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-9 shrink-0"
                aria-label={t("resource.picker.copyValue", { value: option.value })}
                title={t("resource.picker.copyId")}
                onClick={() => void navigator.clipboard.writeText(option.value)}
              >
                <Copy className="size-4" aria-hidden="true" />
              </Button>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-9 shrink-0"
                aria-label={t("resource.picker.removeOption", { name: option.primaryLabel })}
                title={t("resource.action.remove")}
                onClick={() => removeOption(option.value)}
              >
                <X className="size-4" aria-hidden="true" />
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
