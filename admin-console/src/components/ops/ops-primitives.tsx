// Shared presentation helpers for the Operations cockpit (issue #322).
//
// The ops pages (status, config reload, drain, gateway configs, provider
// health, observability) all render the same kinds of read-only status
// evidence: labelled counters, boolean posture chips and health-coloured
// badges. These primitives keep that rendering consistent across the group
// without each page re-deriving the same formatting.
//
// Timestamps used to live here too, as a `formatUnix` built on a bare
// `toLocaleString()` — i.e. formatted in the BROWSER's language rather than the
// console's. #348 moved that to `useFormatUnix` (src/hooks/use-format-unix.ts),
// which needs the active locale and therefore has to be a hook.
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type BadgeVariant = "default" | "secondary" | "destructive" | "outline";

/** A labelled counter tile for the status dashboard grids. */
export function StatTile({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        {hint ? (
          <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

/** A `label: value` row used inside the detail cards. */
export function DefinitionRow({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="grid grid-cols-[minmax(0,12rem)_1fr] gap-2 py-1 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="break-all">{value}</span>
    </div>
  );
}

/**
 * Maps a free-form health/status token onto a badge colour. `ok`/healthy
 * states are neutral (default), degraded states are secondary, and hard
 * failures are destructive so an operator can scan a board at a glance.
 */
export function healthVariant(token: string): BadgeVariant {
  switch (token.toLowerCase()) {
    case "ok":
    case "healthy":
    case "ready":
    case "active":
      return "default";
    case "degraded":
    case "configured":
    case "not_configured":
    case "unknown":
    case "disabled":
      return "secondary";
    case "failed":
    case "error":
    case "version_incompatible":
      return "destructive";
    default:
      return "outline";
  }
}

/** A health-coloured badge. */
export function HealthBadge({ health }: { health: string }) {
  return <Badge variant={healthVariant(health)}>{health}</Badge>;
}

/** A yes/no posture chip; `good` picks whether true or false is the safe state. */
export function BoolBadge({
  value,
  trueLabel = "yes",
  falseLabel = "no",
  good = "true",
}: {
  value: boolean;
  trueLabel?: string;
  falseLabel?: string;
  good?: "true" | "false";
}) {
  const isGood = good === "true" ? value : !value;
  return (
    <Badge variant={isGood ? "default" : "destructive"}>
      {value ? trueLabel : falseLabel}
    </Badge>
  );
}
