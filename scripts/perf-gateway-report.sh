#!/usr/bin/env bash
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

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
  - host network RX/TX throughput sampling over the full run
  - Markdown summary with embedded SVG charts plus raw Vegeta result artifacts

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
  --sample-interval SEC   CPU/RSS/network sample interval. Default: 1
  --pid PID               FerroGate process PID for CPU/RSS sampling.
  --net-device DEVICE     Network device for RX/TX sampling. Default: auto.
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
    --net-device eth0 \
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

sanitize_label() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
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
net_device=""
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
    --net-device)
      net_device="${2:-}"
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
  echo "  net device: ${net_device:-auto}"
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

target_host="$(sed -E 's#^http://([^/:]+).*$#\1#' <<<"$url")"
detect_net_device() {
  if [[ -n "$net_device" ]]; then
    echo "$net_device"
    return
  fi
  if command -v ip >/dev/null 2>&1; then
    ip route get "$target_host" 2>/dev/null | awk '
      {
        for (i = 1; i <= NF; i++) {
          if ($i == "dev" && (i + 1) <= NF) {
            print $(i + 1)
            exit
          }
        }
      }
    '
    return
  fi
  if [[ "$target_host" == "127.0.0.1" || "$target_host" == "localhost" || "$target_host" == "::1" ]]; then
    echo "lo"
  fi
}

net_device="$(detect_net_device)"
if [[ -z "$net_device" && -r /proc/net/dev ]]; then
  net_device="$(awk -F: 'NR > 2 { gsub(/^[ \t]+|[ \t]+$/, "", $1); print $1; exit }' /proc/net/dev)"
fi
[[ -n "$net_device" ]] || die "could not determine network device; pass --net-device DEVICE"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$output_dir" ]]; then
  output_dir="perf-reports/$timestamp"
fi
mkdir -p "$output_dir"

target_file="$output_dir/target.txt"
summary_file="$output_dir/summary.md"
metrics_file="$output_dir/process-metrics.csv"
stages_file="$output_dir/stages.csv"
stage_summary_csv="$output_dir/stage-summary.csv"
overview_svg="$output_dir/overview.svg"
resource_svg="$output_dir/resource-usage.svg"
network_svg="$output_dir/network-io.svg"
visuals_file="$output_dir/.visuals.md"

{
  echo "$method $url"
  for header in "${headers[@]}"; do
    echo "$header"
  done
  if [[ -n "$body_file" ]]; then
    echo "@$body_file"
  fi
} >"$target_file"

echo "epoch,iso8601,cpu_percent,rss_kb,rss_mb,net_device,rx_bps,tx_bps,rx_mbps,tx_mbps" >"$metrics_file"
echo "rate,start_epoch,end_epoch,results_bin,latency_curve_csv,latency_svg,aggregate_json,histogram_txt,plot_html" >"$stages_file"
echo "rate,requests,throughput,success,p50_ms,p95_ms,p99_ms,max_ms,avg_cpu_percent,max_rss_mb" >"$stage_summary_csv"
>"$visuals_file"

sampler_pid=""
cleanup() {
  if [[ -n "$sampler_pid" ]]; then
    kill "$sampler_pid" >/dev/null 2>&1 || true
    wait "$sampler_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

read_net_bytes() {
  local device="$1"
  awk -F'[: ]+' -v device="$device" '
    $2 == device {
      print $3 "," $11
      found = 1
      exit
    }
    END {
      if (!found) {
        print "0,0"
      }
    }
  ' /proc/net/dev
}

if [[ -n "$pid" ]]; then
  ps -p "$pid" >/dev/null 2>&1 || die "pid is not running: $pid"
fi

(
    prev_epoch=""
    prev_rx=""
    prev_tx=""
    while [[ -z "$pid" ]] || ps -p "$pid" >/dev/null 2>&1; do
      epoch="$(date +%s)"
      iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      cpu=""
      rss=""
      rss_mb=""
      if [[ -n "$pid" ]]; then
        row="$(ps -p "$pid" -o %cpu=,rss= | awk '{$1=$1; print}')"
        if [[ -n "$row" ]]; then
          cpu="$(awk '{print $1}' <<<"$row")"
          rss="$(awk '{print $2}' <<<"$row")"
          rss_mb="$(awk -v rss="$rss" 'BEGIN { printf "%.2f", rss / 1024 }')"
        fi
      fi
      rx_bps="0"
      tx_bps="0"
      rx_mbps="0"
      tx_mbps="0"
      if [[ -r /proc/net/dev ]]; then
        net_row="$(read_net_bytes "$net_device")"
        rx_bytes="${net_row%,*}"
        tx_bytes="${net_row#*,}"
        if [[ -n "$prev_epoch" ]]; then
          elapsed=$((epoch - prev_epoch))
          if [[ "$elapsed" -gt 0 ]]; then
            rx_bps="$(awk -v now="$rx_bytes" -v prev="$prev_rx" -v elapsed="$elapsed" 'BEGIN { value = (now - prev) / elapsed; if (value < 0) value = 0; printf "%.0f", value }')"
            tx_bps="$(awk -v now="$tx_bytes" -v prev="$prev_tx" -v elapsed="$elapsed" 'BEGIN { value = (now - prev) / elapsed; if (value < 0) value = 0; printf "%.0f", value }')"
            rx_mbps="$(awk -v value="$rx_bps" 'BEGIN { printf "%.3f", value * 8 / 1000000 }')"
            tx_mbps="$(awk -v value="$tx_bps" 'BEGIN { printf "%.3f", value * 8 / 1000000 }')"
          fi
        fi
        prev_epoch="$epoch"
        prev_rx="$rx_bytes"
        prev_tx="$tx_bytes"
      fi
      if [[ -n "$pid" || -r /proc/net/dev ]]; then
        printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
          "$epoch" "$iso" "$cpu" "$rss" "$rss_mb" "$net_device" "$rx_bps" "$tx_bps" "$rx_mbps" "$tx_mbps"
      fi
      sleep "$sample_interval"
    done
) >>"$metrics_file" &
sampler_pid="$!"

resource_summary_for_window() {
  local start="$1"
  local end="$2"
  awk -F, -v start="$start" -v end="$end" '
    NR > 1 && $1 >= start && $1 <= end && $3 != "" && $4 != "" {
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
      def rfc3339_epoch:
        capture("^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})(?:\\.[0-9]+)?(?<tz>Z|(?<sign>[+-])(?<offset_hour>[0-9]{2}):(?<offset_minute>[0-9]{2}))$") as $ts
        | ([
            ($ts.year | tonumber),
            (($ts.month | tonumber) - 1),
            ($ts.day | tonumber),
            ($ts.hour | tonumber),
            ($ts.minute | tonumber),
            ($ts.second | tonumber)
          ] | mktime)
        - (
            if $ts.tz == "Z" then
              0
            else
              ((if $ts.sign == "+" then 1 else -1 end)
                * ((($ts.offset_hour | tonumber) * 3600) + (($ts.offset_minute | tonumber) * 60)))
            end
          );
      map(select(.error == "" or .error == null))
      | map([
          ((.timestamp | rfc3339_epoch) | floor),
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

write_latency_svg() {
  local curve_csv="$1"
  local svg_file="$2"
  local title="$3"
  awk -F, -v title="$title" '
    function x_pos(i) {
      if (n <= 1) {
        return left
      }
      return left + ((i - 1) * plot_w / (n - 1))
    }
    function y_pos(value) {
      if (max_y <= 0) {
        return top + plot_h
      }
      return top + plot_h - (value * plot_h / max_y)
    }
    function emit_polyline(name, color, values, i, points) {
      points = ""
      for (i = 1; i <= n; i++) {
        points = points sprintf("%.1f,%.1f ", x_pos(i), y_pos(values[i]))
      }
      printf "<polyline points=\"%s\" fill=\"none\" stroke=\"%s\" stroke-width=\"2.2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n", points, color
    }
    BEGIN {
      width = 960
      height = 420
      left = 72
      right = 32
      top = 64
      bottom = 60
      plot_w = width - left - right
      plot_h = height - top - bottom
    }
    NR > 1 {
      n += 1
      epoch[n] = $1
      p50[n] = $4 + 0
      p95[n] = $5 + 0
      p99[n] = $6 + 0
      maxlat[n] = $7 + 0
      if (maxlat[n] > max_y) {
        max_y = maxlat[n]
      }
    }
    END {
      if (max_y <= 0) {
        max_y = 1
      }
      printf "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-label=\"%s\">\n", width, height, width, height, title
      print "<rect width=\"100%\" height=\"100%\" fill=\"#0b0b0c\"/>"
      printf "<text x=\"%d\" y=\"34\" fill=\"#f5f5f5\" font-family=\"Arial, sans-serif\" font-size=\"20\" font-weight=\"700\">%s</text>\n", left, title
      print "<text x=\"72\" y=\"56\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"12\">per-second latency curve, milliseconds</text>"
      for (i = 0; i <= 4; i++) {
        y = top + (plot_h * i / 4)
        value = max_y - (max_y * i / 4)
        printf "<line x1=\"%d\" y1=\"%.1f\" x2=\"%d\" y2=\"%.1f\" stroke=\"#20242a\" stroke-width=\"1\"/>\n", left, y, left + plot_w, y
        printf "<text x=\"18\" y=\"%.1f\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">%.0f</text>\n", y + 4, value
      }
      printf "<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"#3f4652\" stroke-width=\"1\"/>\n", left, top + plot_h, left + plot_w, top + plot_h
      emit_polyline("max", "#6b7280", maxlat)
      emit_polyline("p99", "#f97316", p99)
      emit_polyline("p95", "#38bdf8", p95)
      emit_polyline("p50", "#f8fafc", p50)
      print "<circle cx=\"760\" cy=\"34\" r=\"5\" fill=\"#f8fafc\"/><text x=\"772\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">p50</text>"
      print "<circle cx=\"818\" cy=\"34\" r=\"5\" fill=\"#38bdf8\"/><text x=\"830\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">p95</text>"
      print "<circle cx=\"876\" cy=\"34\" r=\"5\" fill=\"#f97316\"/><text x=\"888\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">p99</text>"
      print "<circle cx=\"760\" cy=\"54\" r=\"5\" fill=\"#6b7280\"/><text x=\"772\" y=\"58\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">max</text>"
      if (n > 0) {
        printf "<text x=\"%d\" y=\"%d\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">start %s</text>\n", left, height - 20, epoch[1]
        printf "<text x=\"%d\" y=\"%d\" text-anchor=\"end\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">end %s</text>\n", left + plot_w, height - 20, epoch[n]
      }
      print "</svg>"
    }
  ' "$curve_csv" >"$svg_file"
}

write_overview_svg() {
  local csv_file="$1"
  local svg_file="$2"
  awk -F, '
    BEGIN {
      width = 960
      height = 420
      left = 76
      right = 38
      top = 72
      bottom = 72
      plot_w = width - left - right
      plot_h = height - top - bottom
    }
    NR > 1 {
      n += 1
      rate[n] = $1 + 0
      throughput[n] = $3 + 0
      success[n] = $4 + 0
      p99[n] = $7 + 0
      if (rate[n] > max_rps) {
        max_rps = rate[n]
      }
      if (throughput[n] > max_rps) {
        max_rps = throughput[n]
      }
    }
    END {
      if (max_rps <= 0) {
        max_rps = 1
      }
      printf "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-label=\"FerroGate performance overview\">\n", width, height, width, height
      print "<rect width=\"100%\" height=\"100%\" fill=\"#0b0b0c\"/>"
      print "<text x=\"76\" y=\"36\" fill=\"#f5f5f5\" font-family=\"Arial, sans-serif\" font-size=\"20\" font-weight=\"700\">FerroGate performance overview</text>"
      print "<text x=\"76\" y=\"58\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"12\">target RPS vs achieved RPS, with p99 labels</text>"
      for (i = 0; i <= 4; i++) {
        y = top + (plot_h * i / 4)
        value = max_rps - (max_rps * i / 4)
        printf "<line x1=\"%d\" y1=\"%.1f\" x2=\"%d\" y2=\"%.1f\" stroke=\"#20242a\" stroke-width=\"1\"/>\n", left, y, left + plot_w, y
        printf "<text x=\"18\" y=\"%.1f\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">%.0f</text>\n", y + 4, value
      }
      if (n > 0) {
        group_w = plot_w / n
        bar_w = group_w * 0.22
        for (i = 1; i <= n; i++) {
          center = left + group_w * (i - 0.5)
          target_h = rate[i] * plot_h / max_rps
          actual_h = throughput[i] * plot_h / max_rps
          target_x = center - bar_w - 3
          actual_x = center + 3
          target_y = top + plot_h - target_h
          actual_y = top + plot_h - actual_h
          printf "<rect x=\"%.1f\" y=\"%.1f\" width=\"%.1f\" height=\"%.1f\" fill=\"#334155\" rx=\"3\"/>\n", target_x, target_y, bar_w, target_h
          printf "<rect x=\"%.1f\" y=\"%.1f\" width=\"%.1f\" height=\"%.1f\" fill=\"#38bdf8\" rx=\"3\"/>\n", actual_x, actual_y, bar_w, actual_h
          printf "<text x=\"%.1f\" y=\"%d\" text-anchor=\"middle\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">%s RPS</text>\n", center, top + plot_h + 24, rate[i]
          printf "<text x=\"%.1f\" y=\"%.1f\" text-anchor=\"middle\" fill=\"#f97316\" font-family=\"Arial, sans-serif\" font-size=\"12\">p99 %.1fms</text>\n", center, target_y - 8, p99[i]
          printf "<text x=\"%.1f\" y=\"%.1f\" text-anchor=\"middle\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">success %.3f</text>\n", center, top + plot_h + 44, success[i]
        }
      }
      print "<rect x=\"738\" y=\"26\" width=\"14\" height=\"14\" fill=\"#334155\" rx=\"2\"/><text x=\"758\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">target</text>"
      print "<rect x=\"812\" y=\"26\" width=\"14\" height=\"14\" fill=\"#38bdf8\" rx=\"2\"/><text x=\"832\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">achieved</text>"
      print "</svg>"
    }
  ' "$csv_file" >"$svg_file"
}

write_resource_svg() {
  local metrics_csv="$1"
  local svg_file="$2"
  awk -F, '
    function x_pos(i) {
      if (n <= 1) {
        return left
      }
      return left + ((i - 1) * plot_w / (n - 1))
    }
    function y_cpu(value) {
      if (max_cpu <= 0) {
        return top + plot_h
      }
      return top + plot_h - (value * plot_h / max_cpu)
    }
    function y_rss(value) {
      if (max_rss <= 0) {
        return top + plot_h
      }
      return top + plot_h - (value * plot_h / max_rss)
    }
    BEGIN {
      width = 960
      height = 420
      left = 72
      right = 32
      top = 64
      bottom = 60
      plot_w = width - left - right
      plot_h = height - top - bottom
    }
    NR > 1 && $3 != "" && $5 != "" {
      n += 1
      epoch[n] = $1
      cpu[n] = $3 + 0
      rss[n] = $5 + 0
      if (cpu[n] > max_cpu) {
        max_cpu = cpu[n]
      }
      if (rss[n] > max_rss) {
        max_rss = rss[n]
      }
    }
    END {
      printf "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-label=\"FerroGate CPU and RSS usage\">\n", width, height, width, height
      print "<rect width=\"100%\" height=\"100%\" fill=\"#0b0b0c\"/>"
      print "<text x=\"72\" y=\"34\" fill=\"#f5f5f5\" font-family=\"Arial, sans-serif\" font-size=\"20\" font-weight=\"700\">FerroGate resource usage</text>"
      if (n == 0) {
        print "<text x=\"72\" y=\"90\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"14\">Process sampling disabled. Pass --pid $(pgrep -n ferrogate) to generate CPU/RSS curves.</text>"
        print "</svg>"
        exit
      }
      if (max_cpu <= 0) {
        max_cpu = 1
      }
      if (max_rss <= 0) {
        max_rss = 1
      }
      print "<text x=\"72\" y=\"56\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"12\">CPU percent and RSS MB sampled during the run</text>"
      for (i = 0; i <= 4; i++) {
        y = top + (plot_h * i / 4)
        printf "<line x1=\"%d\" y1=\"%.1f\" x2=\"%d\" y2=\"%.1f\" stroke=\"#20242a\" stroke-width=\"1\"/>\n", left, y, left + plot_w, y
      }
      cpu_points = ""
      rss_points = ""
      for (i = 1; i <= n; i++) {
        cpu_points = cpu_points sprintf("%.1f,%.1f ", x_pos(i), y_cpu(cpu[i]))
        rss_points = rss_points sprintf("%.1f,%.1f ", x_pos(i), y_rss(rss[i]))
      }
      printf "<polyline points=\"%s\" fill=\"none\" stroke=\"#f97316\" stroke-width=\"2.2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n", cpu_points
      printf "<polyline points=\"%s\" fill=\"none\" stroke=\"#38bdf8\" stroke-width=\"2.2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n", rss_points
      printf "<text x=\"18\" y=\"80\" fill=\"#f97316\" font-family=\"Arial, sans-serif\" font-size=\"11\">CPU max %.1f%%</text>\n", max_cpu
      printf "<text x=\"18\" y=\"100\" fill=\"#38bdf8\" font-family=\"Arial, sans-serif\" font-size=\"11\">RSS max %.1fMB</text>\n", max_rss
      print "<circle cx=\"770\" cy=\"34\" r=\"5\" fill=\"#f97316\"/><text x=\"782\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">CPU %</text>"
      print "<circle cx=\"840\" cy=\"34\" r=\"5\" fill=\"#38bdf8\"/><text x=\"852\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">RSS MB</text>"
      printf "<text x=\"%d\" y=\"%d\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">start %s</text>\n", left, height - 20, epoch[1]
      printf "<text x=\"%d\" y=\"%d\" text-anchor=\"end\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">end %s</text>\n", left + plot_w, height - 20, epoch[n]
      print "</svg>"
    }
  ' "$metrics_csv" >"$svg_file"
}

write_network_svg() {
  local metrics_csv="$1"
  local svg_file="$2"
  awk -F, '
    function x_pos(i) {
      if (n <= 1) {
        return left
      }
      return left + ((i - 1) * plot_w / (n - 1))
    }
    function y_pos(value) {
      if (max_mbps <= 0) {
        return top + plot_h
      }
      return top + plot_h - (value * plot_h / max_mbps)
    }
    BEGIN {
      width = 960
      height = 420
      left = 72
      right = 32
      top = 64
      bottom = 60
      plot_w = width - left - right
      plot_h = height - top - bottom
    }
    NR > 1 {
      n += 1
      epoch[n] = $1
      device = $6
      rx[n] = $9 + 0
      tx[n] = $10 + 0
      if (rx[n] > max_mbps) {
        max_mbps = rx[n]
      }
      if (tx[n] > max_mbps) {
        max_mbps = tx[n]
      }
    }
    END {
      printf "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" viewBox=\"0 0 %d %d\" role=\"img\" aria-label=\"FerroGate network IO usage\">\n", width, height, width, height
      print "<rect width=\"100%\" height=\"100%\" fill=\"#0b0b0c\"/>"
      print "<text x=\"72\" y=\"34\" fill=\"#f5f5f5\" font-family=\"Arial, sans-serif\" font-size=\"20\" font-weight=\"700\">FerroGate network IO</text>"
      if (n == 0) {
        print "<text x=\"72\" y=\"90\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"14\">Network sampling unavailable. Linux /proc/net/dev is required.</text>"
        print "</svg>"
        exit
      }
      if (max_mbps <= 0) {
        max_mbps = 1
      }
      printf "<text x=\"72\" y=\"56\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"12\">RX/TX throughput on %s, Mbps</text>\n", device
      for (i = 0; i <= 4; i++) {
        y = top + (plot_h * i / 4)
        value = max_mbps - (max_mbps * i / 4)
        printf "<line x1=\"%d\" y1=\"%.1f\" x2=\"%d\" y2=\"%.1f\" stroke=\"#20242a\" stroke-width=\"1\"/>\n", left, y, left + plot_w, y
        printf "<text x=\"18\" y=\"%.1f\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">%.1f</text>\n", y + 4, value
      }
      rx_points = ""
      tx_points = ""
      for (i = 1; i <= n; i++) {
        rx_points = rx_points sprintf("%.1f,%.1f ", x_pos(i), y_pos(rx[i]))
        tx_points = tx_points sprintf("%.1f,%.1f ", x_pos(i), y_pos(tx[i]))
      }
      printf "<polyline points=\"%s\" fill=\"none\" stroke=\"#22c55e\" stroke-width=\"2.2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n", rx_points
      printf "<polyline points=\"%s\" fill=\"none\" stroke=\"#a78bfa\" stroke-width=\"2.2\" stroke-linejoin=\"round\" stroke-linecap=\"round\"/>\n", tx_points
      printf "<text x=\"18\" y=\"80\" fill=\"#22c55e\" font-family=\"Arial, sans-serif\" font-size=\"11\">scale max %.1fMbps</text>\n", max_mbps
      print "<circle cx=\"770\" cy=\"34\" r=\"5\" fill=\"#22c55e\"/><text x=\"782\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">RX Mbps</text>"
      print "<circle cx=\"858\" cy=\"34\" r=\"5\" fill=\"#a78bfa\"/><text x=\"870\" y=\"38\" fill=\"#d1d5db\" font-family=\"Arial, sans-serif\" font-size=\"12\">TX Mbps</text>"
      printf "<text x=\"%d\" y=\"%d\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">start %s</text>\n", left, height - 20, epoch[1]
      printf "<text x=\"%d\" y=\"%d\" text-anchor=\"end\" fill=\"#9ca3af\" font-family=\"Arial, sans-serif\" font-size=\"11\">end %s</text>\n", left + plot_w, height - 20, epoch[n]
      print "</svg>"
    }
  ' "$metrics_csv" >"$svg_file"
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
  latency_svg="$output_dir/$label.latency.svg"
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
  write_latency_svg "$curve_csv" "$latency_svg" "Latency curve for ${rate} RPS"

  echo "$rate,$start_epoch,$end_epoch,$results_bin,$curve_csv,$latency_svg,$aggregate_json,$histogram_txt,$plot_html" >>"$stages_file"

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
  printf '%s,%s,%.2f,%.5f,%.2f,%.2f,%.2f,%.2f,%s,%s\n' \
    "$rate" "$requests" "$throughput" "$success" "$p50" "$p95" "$p99" "$max" "$avg_cpu" "$max_rss_mb" \
    >>"$stage_summary_csv"
  {
    echo "### ${rate} RPS Latency Curve"
    echo
    echo "![Latency curve for ${rate} RPS]($(basename "$latency_svg"))"
    echo
  } >>"$visuals_file"
done

cleanup
write_overview_svg "$stage_summary_csv" "$overview_svg"
write_resource_svg "$metrics_file" "$resource_svg"
write_network_svg "$metrics_file" "$network_svg"

{
  echo
  echo "## Visualizations"
  echo
  echo "![Performance overview]($(basename "$overview_svg"))"
  echo
  echo "![Resource usage]($(basename "$resource_svg"))"
  echo
  echo "![Network IO]($(basename "$network_svg"))"
  echo
  cat "$visuals_file"
  echo "## Artifacts"
  echo
  echo "- Target file: \`$target_file\`"
  echo "- Stage index: \`$stages_file\`"
  echo "- Stage summary CSV: \`$stage_summary_csv\`"
  echo "- Process and network metrics: \`$metrics_file\`"
  echo "- Visualizations: \`overview.svg\`, \`resource-usage.svg\`, \`network-io.svg\`, \`*.latency.svg\`"
  echo "- Per-stage files: \`*.aggregate.json\`, \`*.histogram.txt\`, \`*.latency-curve.csv\`, \`*.plot.html\`, \`*.bin\`"
  echo
  echo "## Reading The Report"
  echo
  echo "- Use the stage summary to compare target RPS against achieved RPS and success rate."
  echo "- Use \`overview.svg\` for a quick visual comparison of target and achieved RPS."
  echo "- Use \`*.latency-curve.csv\` to inspect p50/p95/p99/max latency movement over time."
  echo "- Use \`*.latency.svg\` for a ready-to-share visual latency curve per stage."
  echo "- Use \`resource-usage.svg\` and \`process-metrics.csv\` to check whether CPU or RSS climbs steadily during a 5-minute stage."
  echo "- Use \`network-io.svg\` and \`process-metrics.csv\` to inspect RX/TX throughput movement during each stage."
  echo "- Treat failures, falling achieved RPS, rising p99, or monotonically growing RSS as investigation triggers."
} >>"$summary_file"

echo "Performance report written to: $summary_file"
