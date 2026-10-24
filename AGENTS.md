# AGENTS.md

Guidance for AI agents and contributors working in this repository.

## Project

Go binary `easyauth-mcp`: a generic MCP server (stdio) that derives tools from an
OpenAPI 3 spec and calls an API protected by Entra ID / Azure EasyAuth. Module
path `github.com/HBTGmbH/easyauth-mcp`, Go 1.27.3. Licensed under the MIT
License (see `LICENSE`).

Nothing here may be hard-wired to individual endpoints or to one specific
backend: any API behind the same authentication runs through the same code. All
configuration uses the `EASYAUTH_*` prefix.

## Commands

The `Makefile` wraps the common tasks; CI runs the same targets.

```bash
make check     # fmt-check + vet + test (what a PR must pass, writes nothing)
make build     # build bin/easyauth-mcp
make test      # go test ./...
make cover     # tests with a coverage profile
make lint      # golangci-lint run ./... (needs golangci-lint)
make fmt       # gofmt -w .
make tidy      # go mod tidy
make clean     # remove build artifacts
```

Under the hood:

```bash
go build ./...
go test ./... -race
go vet ./...
golangci-lint run ./...   # configured in .golangci.yml
gofmt -l .                # must be empty
```

Before finishing: `make fmt && make check && make lint`.

## CI

- `.github/workflows/ci.yaml` - `make fmt-check`, `make vet`, `make build`,
  `make test` and a cross-build on push/PR.
- `.github/workflows/release.yaml` + `.goreleaser.yaml` - release binaries on
  `v*` tags. Validate config changes with `goreleaser check`.
- `.github/workflows/golangci-lint.yaml` + `.golangci.yml` - golangci-lint
  (pinned version) on push/PR. Only linters that find bugs or security issues
  are enabled, no style linters; gosec and gocritic run with every rule.
  - Discard deliberately ignored errors explicitly (`_, _ = fmt.Fprintf(...)`,
    `defer func() { _ = resp.Body.Close() }()`).
  - Pass large structs by pointer and range over them by index (gocritic
    `hugeParam`/`rangeValCopy`); copy a pointer argument before changing it.
  - Silence a false positive only at its site with
    `//nolint:<linter> // <rule>: <reason>`, never by disabling the rule.
- `.github/workflows/zizmor.yaml` - audits the workflows and Dependabot config
  with [zizmor](https://docs.zizmor.sh/) (`pedantic` persona) on push/PR. Check
  workflow changes locally with `zizmor --persona pedantic .`: pin actions to
  a full commit SHA with a version comment, set `persist-credentials: false`
  on checkout, keep `setup-go` caching off, declare `permissions: {}` at the
  workflow level and grant (and comment) only what each job needs.
- `.github/dependabot.yml` - weekly updates for GitHub Actions and Go modules,
  with a 7-day cooldown.
- CI must stay network-free: tests rely on `httptest`, never on real Entra or
  backend APIs.

## Layout

- `cmd/easyauth-mcp/main.go` - flags/ENV resolution, wiring, MCP server, exit codes.
  No domain logic.
- `cmd/easyauth-mcp/config.go` - flags and `EASYAUTH_*` environment variables.
  Precedence: **flag > env > default**. There is no config file: configuration
  never gets written to disk.
- `cmd/easyauth-mcp/setup.go` - `easyauth_help` (read-only diagnosis) and
  `easyauth_sign_in` (device code, then installs the real tools).
- `internal/spec` - OpenAPI to tool conversion: loading, filtering, naming,
  input schemas, and the `ParamIn` map.
- `internal/auth` - Entra device code flow, token store, refresh, and the
  `Session` that keeps the login non-blocking.
- `internal/api` - generic HTTP executor: path/query/header/body routing via
  `ParamIn`, 401 retry, body limit, error classification.

## Important facts

### API behavior

The server is generic; none of the following may be hard-coded. They are
real-world API behaviors the design must handle.

- An endpoint may be mapped twice, for example `/api/...` and `/rest/...`. The
  default `EASYAUTH_PATH_PREFIX=/api/` keeps the duplicate out.
- **Some `GET` endpoints trigger actions** (background jobs, replications). A
  method filter alone is not enough, which is why `spec.DeniedTags` exists. The
  deny list is **deployment configuration** via `EASYAUTH_DENY_TAGS` /
  `--deny-tags` and is empty by default: nothing is denied unless configured.
- `404` is sometimes a business result (e.g. an empty result set), not a
  failure. It is passed through as content with its status code.
- The spec document is **not** public in every deployment: it can return `401`. The spec fetch therefore reuses an access
  token when one is available.
- CSV output is not offered; the `csv` query parameter is dropped from tool
  schemas, and `Accept` stays `application/json`.
- Task names come from `operationId` when stable, otherwise from
  `METHOD + path`. springdoc's `..._1` suffixes are artifacts, not API.

### Authentication

- Device code flow (public client, no secret). Tokens live in
  `$XDG_STATE_HOME/easyauth-mcp/token.json` (fallback
  `~/.local/state/easyauth-mcp/token.json`), mode `0600`, written atomically.
- Refresh tokens rotate: persist the new one before using the new access token.
- `x-ms-client-principal-id` is set from the `oid` claim, on every request.
- The API may not check `exp`; the server does (`exp - now > 60s`).
- `401` means: refresh once, then retry once. `403` is never a token problem.

## Hard rules

1. **stdout is sacred.** stdout carries only JSON-RPC. Every log line,
   progress message and user prompt goes to stderr or into a tool result. A
   single non-JSON line on stdout breaks the connection.
2. **Never exit on configuration problems.** The server must always come up;
   otherwise a host shows only "Connection closed". Report problems through
   `easyauth_help` or a tool result.
3. **No interactive login on a path that can block the server.** The device
   code goes into a tool result, polling runs in the background
   (`auth.Session`).
4. **No secrets in artifacts.** No tokens, secrets or operational host names in
   logs, errors, tool output, tests or documentation. Placeholders only
   (`<host>`, `<tenant-id>`, `<client-id>`).
5. **Read by default.** Only `GET` is allowed unless configured. Writing needs
   `EASYAUTH_ALLOWED_METHODS=POST` and an explicit tag allowlist.
6. **One user per instance.** Not a multi-user service.
7. **Ask instead of guessing** when behavior of an API or Entra is unclear.
8. **No hard-coded deny list.** `spec.DeniedTags` stays deployment
   configuration (`EASYAUTH_DENY_TAGS` / `--deny-tags`) and empty by default.

## Testing

- Tests are offline: `httptest` servers and the checked-in spec at
  `testdata/openapi-fixture.json`. Never call real Entra or real APIs.
- `cmd/easyauth-mcp/main_test.go` runs the built binary over stdio. Environment
  variables are scrubbed (`envScrubbed`) so tests are hermetic.
- Cover: tool filtering, spec loading (file/URL), the device flow, 401 retry,
  path traversal, body limits, token store permissions and atomicity.
- Keep `go test ./... -race` green.

## Conventions

- No comments unless they explain something non-obvious.
- Errors wrap with `%w`. Close every `resp.Body`. No panics on input.
- Truncate output at rune boundaries, never mid-UTF-8.
- Body limit for tool output: 256 KiB. Auth error bodies: 500 bytes.
- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `<type>(<scope>): <description>`; types `feat`, `fix`, `docs`, `refactor`,
  `test`, `chore`. Imperative, lowercase after the colon, no trailing period.
- Do not commit `token.json`, API responses, or anything under `.idea/`.
