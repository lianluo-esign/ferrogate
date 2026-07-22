import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuth } from "@/hooks/use-auth";
import {
  adminDelete,
  adminGet,
  type AdminSchema,
  gatewayGetBinary,
  gatewayPutBinary,
} from "@/lib/gateway-client";

type AssetSummary = AdminSchema<"AssetSummary">;

const ASSET_TYPES = [
  { label: "CLI tool", value: "cli_tool" },
  { label: "MCP manifest", value: "mcp_manifest" },
  { label: "Skill bundle", value: "skill_bundle" },
  { label: "Static site", value: "static_site" },
  { label: "Config file", value: "config_file" },
];
const ASSETS_QUERY_KEY = ["assets"] as const;
const ASSET_STORAGE_SUMMARY_QUERY_KEY = ["asset-storage-summary"] as const;

function assetPath(assetType: string, name: string, version: string): string {
  return `/v1/assets/${encodeURIComponent(assetType)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function AssetsPage() {
  const { session } = useAuth();
  const apiKey = session!.gatewayApiKey;
  const queryClient = useQueryClient();

  const [assetType, setAssetType] = useState("cli_tool");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const { data, isLoading, error: listError } = useQuery({
    queryKey: ASSETS_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/v1/assets"),
  });

  const {
    data: storageSummary,
    isLoading: isStorageSummaryLoading,
    error: storageSummaryError,
  } = useQuery({
    queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY,
    queryFn: () => adminGet(apiKey, "/v1/assets/storage/summary"),
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose a file to upload");
      if (!name.trim() || !version.trim()) throw new Error("Name and version are required");
      return gatewayPutBinary(
        apiKey,
        assetPath(assetType, name.trim(), version.trim()),
        file,
        file.type,
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY });
      toast.success("Asset pushed");
      setName("");
      setVersion("");
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
    onError: (uploadError: Error) => toast.error(uploadError.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (asset: AssetSummary) =>
      adminDelete(apiKey, "/v1/assets/{asset_type}/{name}/{version}", {
        params: {
          asset_type: asset.asset_type,
          name: asset.name,
          version: asset.version,
        },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ASSETS_QUERY_KEY });
      queryClient.invalidateQueries({ queryKey: ASSET_STORAGE_SUMMARY_QUERY_KEY });
      toast.success("Asset deleted");
    },
    onError: (deleteError: Error) => toast.error(deleteError.message),
  });

  async function handleDownload(asset: AssetSummary) {
    try {
      const blob = await gatewayGetBinary(
        apiKey,
        assetPath(asset.asset_type, asset.name, asset.version),
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = asset.name;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (downloadError) {
      toast.error(downloadError instanceof Error ? downloadError.message : "Download failed");
    }
  }

  const rows = data?.data ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-lg font-semibold">Assets</h1>
        <p className="text-sm text-muted-foreground">
          Tenant-scoped static asset hosting: CLI tool packages, MCP connection manifests, Skill
          bundles, static sites, and config files. Requires the tenant's plan to enable asset
          hosting (see Plans) or a bound role granting the assets.host permission.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Storage quota</CardTitle>
        </CardHeader>
        <CardContent>
          {storageSummaryError ? (
            <p role="alert" className="text-sm text-destructive">
              Failed to load storage usage: {storageSummaryError.message}
            </p>
          ) : isStorageSummaryLoading || !storageSummary ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : (
            <p className="text-sm">
              {formatBytes(storageSummary.used_bytes)} used
              {storageSummary.quota_bytes !== null
                ? ` of ${formatBytes(storageSummary.quota_bytes)}`
                : " (no quota configured)"}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Push an asset</CardTitle>
          <CardDescription>
            Content is scanned and type-checked before it's stored (issue #179) -- a push can be
            rejected with a 422 if it fails those checks.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              uploadMutation.mutate();
            }}
          >
            <div className="grid gap-2">
              <Label htmlFor="asset-type">Asset type</Label>
              <Select value={assetType} onValueChange={setAssetType}>
                <SelectTrigger id="asset-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ASSET_TYPES.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-name">Name</Label>
              <Input
                id="asset-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="my-tool"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-version">Version</Label>
              <Input
                id="asset-version"
                value={version}
                onChange={(event) => setVersion(event.target.value)}
                placeholder="1.0.0"
                required
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="asset-file">File</Label>
              <Input
                id="asset-file"
                type="file"
                ref={fileInputRef}
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                required
              />
            </div>
            <div className="sm:col-span-2">
              <Button type="submit" disabled={uploadMutation.isPending}>
                {uploadMutation.isPending ? "Pushing…" : "Push"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {listError && (
        <p role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Failed to load assets: {listError.message}
        </p>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Type</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Content type</TableHead>
              <TableHead>Content hash</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Storage</TableHead>
              <TableHead className="w-32" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  Loading…
                </TableCell>
              </TableRow>
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  No assets yet.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((asset) => (
                <TableRow key={asset.id}>
                  <TableCell>{asset.asset_type}</TableCell>
                  <TableCell>{asset.name}</TableCell>
                  <TableCell>{asset.version}</TableCell>
                  <TableCell>{asset.content_type}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {asset.content_hash.slice(0, 12)}...
                  </TableCell>
                  <TableCell>{formatBytes(asset.size_bytes)}</TableCell>
                  <TableCell>{asset.storage_backed ? "Bucket" : "Inline"}</TableCell>
                  <TableCell className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => handleDownload(asset)}>
                      Download
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => deleteMutation.mutate(asset)}
                    >
                      Delete
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
