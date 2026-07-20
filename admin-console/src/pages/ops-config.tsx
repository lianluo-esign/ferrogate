// Config validate / reload (issue #322) — the flagship ops flow over
// POST /admin/v1/config/validate and POST /admin/v1/config/reload.
//
// The safety contract is validate-before-reload: the operator pastes a
// candidate config (or points at the process source file), runs VALIDATE
// first, and Reload stays DISABLED until that exact candidate came back
// `valid: true`. Any edit to the format or the config text invalidates the
// prior validation and re-locks Reload, so a hot reload can never apply an
// unvalidated (or since-changed) config. Reload itself sits behind a
// confirmation dialog because it swaps the running gateway config.
import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
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
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { BoolBadge, DefinitionRow } from "@/components/ops/ops-primitives";
import { useAuth } from "@/hooks/use-auth";
import { adminPost, type AdminSchema } from "@/lib/gateway-client";

type ValidateRequest = AdminSchema<"AdminConfigValidateRequest">;
type ValidateResponse = AdminSchema<"AdminConfigValidateResponse">;
type ReloadResponse = AdminSchema<"AdminConfigReloadResponse">;

type ConfigFormat = "file" | "toml" | "yaml" | "caddyfile";

const FORMAT_LABELS: Record<ConfigFormat, string> = {
  file: "Process source file",
  toml: "Inline TOML",
  yaml: "Inline YAML",
  caddyfile: "Inline Caddyfile",
};

function buildRequest(
  format: ConfigFormat,
  configText: string,
  filename: string,
): ValidateRequest {
  switch (format) {
    case "file":
      return { source: "file" };
    case "toml":
      return { config_toml: configText };
    case "yaml":
      return { config_yaml: configText };
    case "caddyfile":
      return {
        config_caddyfile: configText,
        filename: filename.trim() || undefined,
      };
  }
}

export default function OpsConfigPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;

  const [format, setFormat] = useState<ConfigFormat>("file");
  const [configText, setConfigText] = useState("");
  const [filename, setFilename] = useState("candidate.Caddyfile");
  const [validation, setValidation] = useState<ValidateResponse | null>(null);
  const [reloadResult, setReloadResult] = useState<ReloadResponse | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  // Editing the candidate re-locks Reload: the last validation no longer
  // describes what's in the editor, so it can't authorize a reload.
  function invalidatePriorValidation() {
    setValidation(null);
    setReloadResult(null);
  }

  const request = useMemo(
    () => buildRequest(format, configText, filename),
    [format, configText, filename],
  );

  const inlineEmpty = format !== "file" && configText.trim() === "";

  const validateMutation = useMutation({
    mutationFn: () =>
      adminPost(apiKey, "/admin/v1/config/validate", request),
    onSuccess: (result) => {
      setValidation(result);
      setReloadResult(null);
      if (result.valid) {
        toast.success("Config is valid — reload unlocked");
      } else {
        toast.error("Config is invalid");
      }
    },
    onError: (error: Error) => {
      // A 400/413 (unparseable / too large) never yields a validation body;
      // keep Reload locked and surface the transport error.
      setValidation(null);
      toast.error(`Validation failed: ${error.message}`);
    },
  });

  const reloadMutation = useMutation({
    mutationFn: () => adminPost(apiKey, "/admin/v1/config/reload", request),
    onSuccess: (result) => {
      setReloadResult(result);
      if (result.committed) {
        toast.success(`Config reloaded (${result.mode})`);
        // A committed reload consumes this validation; require a fresh one
        // before the next reload.
        setValidation(null);
      } else {
        toast.error("Reload did not commit");
      }
    },
    onError: (error: Error) => {
      toast.error(`Reload failed: ${error.message}`);
    },
  });

  const canReload =
    validation?.valid === true &&
    !validateMutation.isPending &&
    !reloadMutation.isPending;

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Config validate &amp; reload</h1>
        <p className="text-sm text-muted-foreground">
          Validate a candidate gateway config before applying it. Reload stays
          locked until the current candidate validates cleanly; any edit
          re-locks it.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Candidate config</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-2 sm:max-w-xs">
            <Label htmlFor="config-format">Source</Label>
            <Select
              value={format}
              onValueChange={(value) => {
                setFormat(value as ConfigFormat);
                invalidatePriorValidation();
              }}
            >
              <SelectTrigger id="config-format" aria-label="Config source">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(FORMAT_LABELS) as ConfigFormat[]).map((value) => (
                  <SelectItem key={value} value={value}>
                    {FORMAT_LABELS[value]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {format === "file" ? (
            <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground">
              Validates the config file that started this gateway process. No
              inline config is sent.
            </p>
          ) : (
            <>
              {format === "caddyfile" ? (
                <div className="grid gap-2 sm:max-w-xs">
                  <Label htmlFor="config-filename">Filename</Label>
                  <input
                    id="config-filename"
                    className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm"
                    value={filename}
                    onChange={(event) => {
                      setFilename(event.target.value);
                      invalidatePriorValidation();
                    }}
                  />
                </div>
              ) : null}
              <div className="grid gap-2">
                <Label htmlFor="config-text">Config</Label>
                <Textarea
                  id="config-text"
                  className="min-h-56 font-mono text-xs"
                  placeholder={`Paste ${FORMAT_LABELS[format]} here`}
                  value={configText}
                  onChange={(event) => {
                    setConfigText(event.target.value);
                    invalidatePriorValidation();
                  }}
                />
              </div>
            </>
          )}

          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => validateMutation.mutate()}
              disabled={validateMutation.isPending || inlineEmpty}
            >
              {validateMutation.isPending ? "Validating..." : "Validate"}
            </Button>
            <Button
              variant="destructive"
              disabled={!canReload}
              onClick={() => setConfirmOpen(true)}
            >
              Reload
            </Button>
          </div>
        </CardContent>
      </Card>

      {validation ? (
        <Card
          data-testid="validation-result"
          className={
            validation.valid ? "border-primary/40" : "border-destructive/50"
          }
        >
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              Validation result
              <BoolBadge
                value={validation.valid}
                trueLabel="valid"
                falseLabel="invalid"
              />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="divide-y">
              <DefinitionRow
                label="Listener reload required"
                value={
                  <BoolBadge
                    value={validation.listener_reload_required}
                    trueLabel="listener restart"
                    falseLabel="hot reload"
                    good="false"
                  />
                }
              />
              {validation.reload_mode ? (
                <DefinitionRow label="Reload mode" value={validation.reload_mode} />
              ) : null}
              {validation.reload_reason ? (
                <DefinitionRow label="Reason" value={validation.reload_reason} />
              ) : null}
              {validation.snapshot ? (
                <DefinitionRow label="Snapshot" value={validation.snapshot} />
              ) : null}
              {validation.error ? (
                <DefinitionRow
                  label="Error"
                  value={
                    <pre className="whitespace-pre-wrap break-all font-mono text-xs text-destructive">
                      {validation.error}
                    </pre>
                  }
                />
              ) : null}
            </div>
            {validation.valid ? (
              <p className="mt-3 text-sm text-muted-foreground">
                Reload is unlocked for this candidate.
              </p>
            ) : (
              <p className="mt-3 text-sm text-destructive">
                Fix the errors above and re-validate; reload stays locked.
              </p>
            )}
          </CardContent>
        </Card>
      ) : null}

      {reloadResult ? (
        <Card data-testid="reload-result">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              Reload result
              <Badge variant={reloadResult.committed ? "default" : "destructive"}>
                {reloadResult.committed ? "committed" : "not committed"}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="divide-y">
              <DefinitionRow label="Mode" value={reloadResult.mode} />
              <DefinitionRow
                label="Active snapshot"
                value={reloadResult.active_snapshot ?? "-"}
              />
              <DefinitionRow
                label="Candidate snapshot"
                value={reloadResult.candidate_snapshot ?? "-"}
              />
              {reloadResult.error ? (
                <DefinitionRow
                  label="Error"
                  value={<span className="text-destructive">{reloadResult.error}</span>}
                />
              ) : null}
            </div>
          </CardContent>
        </Card>
      ) : null}

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Reload gateway config?</AlertDialogTitle>
            <AlertDialogDescription>
              This applies the validated candidate to the running gateway,
              swapping the active config
              {validation?.listener_reload_required
                ? " and restarting listeners (in-flight connections may be dropped)"
                : " via hot reload"}
              . This affects live traffic.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                setConfirmOpen(false);
                reloadMutation.mutate();
              }}
            >
              Reload now
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
