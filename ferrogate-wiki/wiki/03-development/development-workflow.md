---
title: Development workflow
---

# Development workflow

## Local development

```bash
cargo run -- validate --config Ferrogate/Caddyfile
cargo run -- reload --config Ferrogate/Caddyfile
cargo run -- run --config Ferrogate/Caddyfile
```

`validate` 和当前 P2 占位 `reload` 都会输出候选配置 snapshot id。`reload` 在 Pingora-backed 热重载完成前只做配置加载和校验，不会声称已经替换运行中配置。

`/admin/status` 会返回当前 active 配置 snapshot，后续 Pingora-backed reload 会用它验证 failed candidate 不会污染运行中配置。

Then test:

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/v1/models
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}'
```

P3 当前已经完成 OpenAI-compatible 非流式 HTTP dispatch 和 `stream=true` SSE response forwarding MVP。`/v1/chat/completions` 会完成鉴权、租户上下文、模型路由、provider request planning，并把请求转发到 HTTP OpenAI-compatible upstream。当前 streaming 切片会透传 provider 的 `text/event-stream` 响应体；真正的上游到下游增量式边读边写、HTTPS provider dispatch、usage 提取和错误归一化继续作为后续 P3 切片推进。

P3 变更必须至少运行：

```bash
cargo test -p ferrogate-providers -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_auth -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_dispatch_errors -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_runtime -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_perf -- --nocapture
```

## Documentation workflow

1. Edit notes in `wiki/` with Obsidian.
2. Use wiki links like `[[02-architecture/system-architecture]]`.
3. Build the static site with:

```bash
./scripts/build-wiki-site.sh
```

4. Preview with:

```bash
cd wiki-site
npm run docs:serve
```

## Commit workflow

- Keep product and architecture changes documented in `wiki/`.
- Add Architecture Decision Records for major design changes.
- Keep generated `wiki-site/public/` out of git unless a deployment target explicitly requires it.
