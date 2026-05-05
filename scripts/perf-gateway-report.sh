#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/perf-gateway-report.sh --url URL [options]

Generates a reproducible FerroGate load-test report with:
  - staged target RPS tests, defaulting to 20k, 50k, and 100k requests/sec
  - high connection concurrency, defaulting to 10k open connections
  - per-second latency curve CSVs with p50/p95/p99
  - optional FerroGate process CPU/RSS sampling over the full run
  - Markdown summary plus raw Vegeta result artifacts

Required external tools:
  vegeta, jq, awk, ps

Options:
  --url URL                Target gateway URL, for example http://127.0.0.1:8080/healthz
  --method METHOD         HTTP method. Default: GET
  --header HEADER         Extra HTTP header. May be repeated.
  --body-file PATH        Request body file for POST/PUT style tests.
  --rates CSV             Target RPS stages. Default: 20000,50000,100000
  --connections N         Vegeta max open idle connections per target host. Default: 10000
  --workers N             Vegeta initial worker count. Default: 1024
  --duration DURATION     Duration per RPS stage. Default: 5m
  --timeout DURATION      Per-request timeout. Default: 10s
  --sample-interval SEC   CPU/RSS sample interval. Default: 1
  --pid PID               FerroGate process PID for CPU/RSS sampling.
  --output-dir DIR        Output directory. Default: perf-reports/<UTC timestamp>
  --dry-run               Print the test plan without running load.
  -h, --help              Show this help.

Examples:
  scripts/perf-gateway-report.sh \
    --url http://127.0.0.1:8080/healthz \
    --pid "$(pgrep -n ferrogate)"

  scripts/perf-gateway-report.sh \
    --url http://127.0.0.1:8080/v1/chat/completions \
    --method POST \
    --header 'Authorization: Bearer dev-secret' \
    --header 'Content-Type: application/json' \
    --body-file ./perf-chat-body.json \
    --rates 20000,50000,100000 \
    --connections 10000 \
    --duration 5m
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

duration_seconds() {
  local raw="$1"
  case "$raw" in
    *ms) die "millisecond durations are not supported for stage timing: $raw" ;;
    *s) echo "${raw%s}" ;;
    *m) awk -v value="${raw%m}" 'BEGIN { printf "%.0f\n", value * 60 }' ;;
    *h) awk -v value="${raw%h}" 'BEGIN { printf "%.0f\n", value * 3600 }' ;;
    '') die "empty duration" ;;
    *) echo "$raw" ;;
  esac
}

sanitize_label() {
  echo "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

url=""
method="GET"
rates="20000,50000,100000"
connections="10000"
workers="1024"
duration="5m"
timeout="10s"
sample_interval="1"
pid=""
body_file=""
output_dir=""
dry_run="0"
headers=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      url="${2:-}"
      shift 2
      ;;
    --method)
      method="${2:-}"
      shift 2
      ;;
    --header)
      headers+=("${2:-}")
      shift 2
      ;;
    --body-file)
      body_file="${2:-}"
      shift 2
      ;;
    --rates)
      rates="${2:-}"
      shift 2
      ;;
    --connections)
      connections="${2:-}"
      shift 2
      ;;
    --workers)
      workers="${2:-}"
      shift 2
      ;;
    --duration)
      duration="${2:-}"
      shift 2
      ;;
    --timeout)
      timeout="${2:-}"
      shift 2
      ;;
    --sample-interval)
      sample_interval="${2:-}"
      shift 2
      ;;
    --pid)
      pid="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$url" ]] || die "--url is required"
[[ "$url" == http://* ]] || die "only local/plain HTTP targets are supported by this report script: $url"
[[ -z "$body_file" || -f "$body_file" ]] || die "body file does not exist: $body_file"

IFS=',' read -r -a rate_list <<<"$rates"
[[ "${#rate_list[@]}" -gt 0 ]] || die "--rates must include at least one value"

if [[ "$dry_run" == "1" ]]; then
  echo "FerroGate performance report dry run"
  echo "  url: $url"
  echo "  method: $method"
  echo "  rates: $rates"
  echo "  connections: $connections"
  echo "  workers: $workers"
  echo "  duration per stage: $duration"
  echo "  timeout: $timeout"
  echo "  pid: ${pid:-not set}"
  echo "  body file: ${body_file:-not set}"
  for header in "${headers[@]}"; do
    echo "  header: $header"
  done
  exit 0
fi

need_cmd vegeta
need_cmd jq
need_cmd awk
need_cmd ps
need_cmd date

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$output_dir" ]]; then
  output_dir="perf-reports/$timestamp"
fi
mkdir -p "$output_dir"

target_file="$output_dir/target.txt"
summary_file="$output_dir/summary.md"
metrics_file="$output_dir/process-metrics.csv"
stages_file="$output_dir/stages.csv"

{
  echo "$method $url"
  for header in "${headers[@]}"; do
    echo "$header"
  done
  if [[ -n "$body_file" ]]; then
    echo "@$body_file"
  fi
} >"$target_file"

echo "epoch,iso8601,cpu_percent,rss_kb,rss_mb" >"$metrics_file"
echo "rate,start_epoch,end_epoch,results_bin,latency_curve_csv,aggregate_json,histogram_txt" >"$stages_file"

sampler_pid=""
cleanup() {
  if [[ -n "$sampler_pid" ]]; then
    kill "$sampler_pid" >/dev/null 2>&1 || true
    wait "$sampler_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ -n "$pid" ]]; then
  ps -p "$pid" >/dev/null 2>&1 || die "pid is not running: $pid"
  (
    while ps -p "$pid" >/dev/null 2>&1; do
      epoch="$(date +%s)"
      iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      row="$(ps -p "$pid" -o %cpu=,rss= | awk '{$1=$1; print}')"
      if [[ -n "$row" ]]; then
        cpu="$(awk '{print $1}' <<<"$row")"
        rss="$(awk '{print $2}' <<<"$row")"
        awk -v epoch="$epoch" -v iso="$iso" -v cpu="$cpu" -v rss="$rss" \
          'BEGIN { printf "%s,%s,%.2f,%d,%.2f\n", epoch, iso, cpu, rss, rss / 1024 }'
      fi
      sleep "$sample_interval"
    done
  ) >>"$metrics_file" &
  sampler_pid="$!"
fi

resource_summary_for_window() {
  local start="$1"
  local end="$2"
  awk -F, -v start="$start" -v end="$end" '
    NR > 1 && $1 >= start && $1 <= end {
      n += 1
      cpu += $3
      if ($4 > max_rss) {
        max_rss = $4
      }
    }
    END {
      if (n == 0) {
        printf "n/a,n/a"
      } else {
        printf "%.2f,%.2f", cpu / n, max_rss / 1024
      }
    }
  ' "$metrics_file"
}

write_latency_curve() {
  local results_bin="$1"
  local curve_csv="$2"
  echo "epoch,iso8601,count,p50_ms,p95_ms,p99_ms,max_ms" >"$curve_csv"
  vegeta encode -to=json "$results_bin" |
    jq -s -r '
      map(select(.error == "" or .error == null))
      | map([
          ((.timestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) | floor),
          (.latency / 1000000)
        ])
      | group_by(.[0])[]
      | sort_by(.[1]) as $rows
      | ($rows | length) as $n
      | ($rows[0][0]) as $epoch
      | [
          $epoch,
          ($epoch | strftime("%Y-%m-%dT%H:%M:%SZ")),
          $n,
          ($rows[((($n - 1) * 0.50) | floor)][1]),
          ($rows[((($n - 1) * 0.95) | floor)][1]),
          ($rows[((($n - 1) * 0.99) | floor)][1]),
          ($rows[$n - 1][1])
        ]
      | @csv
    ' >>"$curve_csv"
}

{
  echo "# FerroGate Performance Report"
  echo
  echo "- Generated: $timestamp"
  echo "- Target: \`$method $url\`"
  echo "- Target rates: \`$rates\` requests/sec"
  echo "- Connections: \`$connections\`"
  echo "- Workers: \`$workers\`"
  echo "- Duration per stage: \`$duration\`"
  echo "- Timeout: \`$timeout\`"
  echo "- Resource PID: \`${pid:-not sampled}\`"
  echo
  echo "## Stage Summary"
  echo
  echo "| Target RPS | Requests | Achieved RPS | Success | p50 ms | p95 ms | p99 ms | Max ms | Avg CPU % | Max RSS MB |"
  echo "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
} >"$summary_file"

for rate in "${rate_list[@]}"; do
  rate="$(echo "$rate" | xargs)"
  [[ -n "$rate" ]] || continue
  label="$(sanitize_label "rps-$rate")"
  results_bin="$output_dir/$label.bin"
  aggregate_json="$output_dir/$label.aggregate.json"
  histogram_txt="$output_dir/$label.histogram.txt"
  curve_csv="$output_dir/$label.latency-curve.csv"
  plot_html="$output_dir/$label.plot.html"

  echo "==> Running rate=$rate/s duration=$duration connections=$connections"
  start_epoch="$(date +%s)"
  vegeta attack \
    -targets="$target_file" \
    -rate="${rate}/1s" \
    -duration="$duration" \
    -connections="$connections" \
    -workers="$workers" \
    -timeout="$timeout" \
    -name="$label" \
    >"$results_bin"
  end_epoch="$(date +%s)"

  vegeta report -type=json "$results_bin" >"$aggregate_json"
  vegeta report -type='hist[0,10ms,25ms,50ms,100ms,250ms,500ms,1s,2s,5s]' "$results_bin" >"$histogram_txt"
  vegeta plot "$results_bin" >"$plot_html"
  write_latency_curve "$results_bin" "$curve_csv"

  echo "$rate,$start_epoch,$end_epoch,$results_bin,$curve_csv,$aggregate_json,$histogram_txt" >>"$stages_file"

  requests="$(jq -r '.requests' "$aggregate_json")"
  throughput="$(jq -r '.throughput' "$aggregate_json")"
  success="$(jq -r '.success' "$aggregate_json")"
  p50="$(jq -r '.latencies."50th" / 1000000' "$aggregate_json")"
  p95="$(jq -r '.latencies."95th" / 1000000' "$aggregate_json")"
  p99="$(jq -r '.latencies."99th" / 1000000' "$aggregate_json")"
  max="$(jq -r '.latencies.max / 1000000' "$aggregate_json")"
  resource_summary="$(resource_summary_for_window "$start_epoch" "$end_epoch")"
  avg_cpu="${resource_summary%,*}"
  max_rss_mb="${resource_summary#*,}"

  printf '| %s | %s | %.2f | %.5f | %.2f | %.2f | %.2f | %.2f | %s | %s |\n' \
    "$rate" "$requests" "$throughput" "$success" "$p50" "$p95" "$p99" "$max" "$avg_cpu" "$max_rss_mb" \
    >>"$summary_file"
done

{
  echo
  echo "## Artifacts"
  echo
  echo "- Target file: \`$target_file\`"
  echo "- Stage index: \`$stages_file\`"
  echo "- Process metrics: \`$metrics_file\`"
  echo "- Per-stage files: \`*.aggregate.json\`, \`*.histogram.txt\`, \`*.latency-curve.csv\`, \`*.plot.html\`, \`*.bin\`"
  echo
  echo "## Reading The Report"
  echo
  echo "- Use the stage summary to compare target RPS against achieved RPS and success rate."
  echo "- Use \`*.latency-curve.csv\` to inspect p50/p95/p99/max latency movement over time."
  echo "- Use \`process-metrics.csv\` to check whether CPU or RSS climbs steadily during a 5-minute stage."
  echo "- Treat failures, falling achieved RPS, rising p99, or monotonically growing RSS as investigation triggers."
} >>"$summary_file"

echo "Performance report written to: $summary_file"
