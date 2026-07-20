// Shared building blocks for the Worker ops pages (issue #320): the
// register/rotate credential-shown-once dialog (mirrors the virtual-key
// "save this secret now" pattern in resource-page.tsx / #249 mTLS identity)
// plus helpers that surface the customer-reported correlation triple
// (request_id / trace_id / agent_run_id, #305) and the parent action
// fingerprint (#307) out of a self-hosted worker's reported `event_json`.
//
// Self-hosted worker telemetry is customer-reported evidence
// (`trust_level: reported_by_self_hosted_worker`), so the correlation ids are
// NOT structured contract columns — they live inside the reported event
// document. These helpers parse that document defensively (never throw on
// malformed JSON) and pull the correlation fields when present.
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

/** Customer-reported (#305/#307) correlation fields lifted out of event_json. */
export interface ReportedCorrelation {
  requestId: string | null;
  traceId: string | null;
  agentRunId: string | null;
  parentActionFingerprint: string | null;
}

const EMPTY_CORRELATION: ReportedCorrelation = {
  requestId: null,
  traceId: null,
  agentRunId: null,
  parentActionFingerprint: null,
};

function pickString(
  source: Record<string, unknown>,
  ...keys: string[]
): string | null {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value.length > 0) return value;
  }
  return null;
}

/**
 * Parses a single self-hosted worker reported `event_json` document and lifts
 * the correlation triple + parent action fingerprint. Accepts the ids either
 * at the document root or nested under a `correlation` object. Malformed or
 * non-object JSON yields an all-null result rather than throwing.
 */
export function parseReportedCorrelation(
  eventJson: string | null | undefined,
): ReportedCorrelation {
  if (!eventJson) return EMPTY_CORRELATION;
  let doc: unknown;
  try {
    doc = JSON.parse(eventJson);
  } catch {
    return EMPTY_CORRELATION;
  }
  if (typeof doc !== "object" || doc === null) return EMPTY_CORRELATION;
  const root = doc as Record<string, unknown>;
  const nested =
    typeof root.correlation === "object" && root.correlation !== null
      ? (root.correlation as Record<string, unknown>)
      : {};
  return {
    requestId:
      pickString(root, "request_id") ?? pickString(nested, "request_id"),
    traceId: pickString(root, "trace_id") ?? pickString(nested, "trace_id"),
    agentRunId:
      pickString(root, "agent_run_id") ?? pickString(nested, "agent_run_id"),
    parentActionFingerprint:
      pickString(
        root,
        "parent_action_fingerprint",
        "parent_action_sha256",
      ) ??
      pickString(nested, "parent_action_fingerprint", "parent_action_sha256"),
  };
}

/**
 * Folds every reported event's correlation into one aggregate, taking the
 * first non-null value seen for each field (events are already time-ordered).
 */
export function aggregateReportedCorrelation(
  eventJsons: (string | null | undefined)[],
): ReportedCorrelation {
  return eventJsons.reduce<ReportedCorrelation>((acc, json) => {
    const parsed = parseReportedCorrelation(json);
    return {
      requestId: acc.requestId ?? parsed.requestId,
      traceId: acc.traceId ?? parsed.traceId,
      agentRunId: acc.agentRunId ?? parsed.agentRunId,
      parentActionFingerprint:
        acc.parentActionFingerprint ?? parsed.parentActionFingerprint,
    };
  }, EMPTY_CORRELATION);
}

/** Violet "reported by worker" trust badge, matching the self-hosted trust level. */
export function ReportedTrustBadge() {
  return (
    <Badge className="border-transparent bg-violet-100 text-violet-900 dark:bg-violet-950 dark:text-violet-200">
      reported by worker
    </Badge>
  );
}

/** Status badge variant for a self-hosted worker record's free-form status. */
export function workerStatusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  const normalized = status.toLowerCase();
  if (normalized === "active" || normalized === "ready") return "default";
  if (normalized === "revoked" || normalized === "failed") return "destructive";
  if (normalized === "stale") return "outline";
  return "secondary";
}

/**
 * Credential-shown-once dialog for register / rotate. The self-hosted worker
 * identity fingerprint is the durable mTLS credential (#249): after a
 * registration or rotation it is surfaced exactly once with a copy button and
 * a "won't be shown again" warning, mirroring virtual-key issuance.
 */
export function CredentialRevealDialog({
  open,
  onClose,
  title,
  description,
  credentialLabel,
  credential,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description: string;
  credentialLabel: string;
  credential: string | null;
}) {
  async function copy() {
    if (!credential) return;
    try {
      await navigator.clipboard.writeText(credential);
      toast.success(`${credentialLabel} copied`);
    } catch {
      toast.error(`Could not copy ${credentialLabel.toLowerCase()}; it is shown above.`);
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={(next) => !next && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <div className="grid gap-1">
          <span className="text-xs font-medium text-muted-foreground">
            {credentialLabel}
          </span>
          <code
            className="block break-all rounded-md bg-muted p-3 font-mono text-sm"
            data-testid="revealed-credential"
          >
            {credential ?? "—"}
          </code>
          <p className="text-xs font-medium text-destructive">
            This value will not be shown again. Store it somewhere safe.
          </p>
        </div>
        <AlertDialogFooter>
          <Button type="button" variant="outline" onClick={() => void copy()}>
            Copy
          </Button>
          <AlertDialogAction onClick={onClose}>Done</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
