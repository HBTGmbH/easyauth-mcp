# easyauth-mcp

Generic MCP server (stdio) that derives tools from an OpenAPI 3 spec and calls an
API protected by Entra ID / Azure EasyAuth.

The server reads an OpenAPI document, exposes one MCP tool per operation, and
forwards each call to the API. Nothing is tied to individual endpoints or to one
specific backend: any HBT service behind the same authentication works the same
way.

## Quick start

```bash
# 1. install (or use your local checkout, see Installation)
go install github.com/HBTGmbH/easyauth-mcp/cmd/easyauth-mcp@latest

# 2. register the binary in your MCP host (see below)

# 3. in the chat: call easyauth_sign_in, confirm the code, call it again
```

Configuration is passed as environment variables by the MCP host. There is no
setup command and no config file; the only state on disk is the token store.

The binary then lives in `$(go env GOPATH)/bin/easyauth-mcp`; use that path (or an
absolute path to a locally built binary) as `command` in the host
configuration below.

### opencode

Add the server to your opencode configuration. For **local** servers the
environment block is called `environment` - an `env` key is ignored silently, so
the server would start without any configuration.

```json
{
  "mcp": {
    "easyauth": {
      "type": "local",
      "command": ["/path/to/bin/easyauth-mcp"],
      "enabled": true,
      "environment": {
        "EASYAUTH_BASE_URL": "https://<host>",
        "EASYAUTH_OPENAPI": "https://<host>/api/doc/api-docs",
        "EASYAUTH_TENANT_ID": "<tenant-id>",
        "EASYAUTH_CLIENT_ID": "<client-id>",
        "EASYAUTH_SCOPE": "api://<client-id>/user_impersonation",
        "EASYAUTH_ALLOWED_TAGS": "favorite,daily report,working days,overtime,order,report"
      }
    }
  }
}
```

Restart opencode. Then, in the chat:

1. Call `easyauth_sign_in`. The device code and verification URI appear in the tool
   result.
2. Confirm the code in the browser.
3. Call `easyauth_sign_in` again. It reports that the tools are now available.
4. Use the API tools, e.g. `get_api_favorite`.

If a required variable is missing, the server exposes `easyauth_help` instead; its
result names the variables the process actually saw.

### Claude Desktop

> Not tested. The configuration format below follows the documented Claude
> Desktop layout; only opencode has been verified with this server.

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "easyauth": {
      "command": "/path/to/bin/easyauth-mcp",
      "env": {
        "EASYAUTH_BASE_URL": "https://<host>",
        "EASYAUTH_OPENAPI": "https://<host>/api/doc/api-docs",
        "EASYAUTH_TENANT_ID": "<tenant-id>",
        "EASYAUTH_CLIENT_ID": "<client-id>",
        "EASYAUTH_SCOPE": "api://<client-id>/user_impersonation",
        "EASYAUTH_ALLOWED_TAGS": "favorite,daily report,working days,overtime,order,report"
      }
    }
  }
}
```

Restart Claude Desktop and follow the same sign-in steps. Because stderr is not
shown in the chat, the device code must come back through the tool result - which
is what `easyauth_sign_in` does. If the server is not listed at all, check the host
logs: a startup problem is reported through the tool result, not by exiting.

## Installation

With Go 1.27.3 or newer:

```bash
go install github.com/HBTGmbH/easyauth-mcp/cmd/easyauth-mcp@latest
```

From a local checkout use

```bash
go install ./cmd/easyauth-mcp
```

which places `easyauth-mcp` in `$(go env GOPATH)/bin`. Make sure that directory is
on your `PATH`, or install elsewhere:

```bash
GOBIN="$HOME/.local/bin" go install ./cmd/easyauth-mcp
```

Alternatively build a single binary and move it into your `PATH`:

```bash
go build -o /usr/local/bin/easyauth-mcp ./cmd/easyauth-mcp
```

Released binaries for Linux and macOS (amd64/arm64) and Windows (amd64) are
attached to every `v*` tag (see [Releases](#releases)).

## Configuration

Precedence: **flag > environment variable > default**.

| Env variable                | Meaning                                                              | Required    |
|-----------------------------|----------------------------------------------------------------------|-------------|
| `EASYAUTH_BASE_URL`         | API base URL, e.g. `https://<host>` or `http://localhost:8080`       | yes         |
| `EASYAUTH_OPENAPI`          | path or URL of the OpenAPI 3 JSON spec                               | yes         |
| `EASYAUTH_LOGIN_URL`        | Entra ID login base URL (default public cloud)                       | no          |
| `EASYAUTH_TENANT_ID`        | Entra tenant (GUID)                                                  | auth mode   |
| `EASYAUTH_CLIENT_ID`        | client ID of the app registration                                    | auth mode   |
| `EASYAUTH_SCOPE`            | `api://<client-id>/user_impersonation`                               | auth mode   |
| `EASYAUTH_TOKEN_STORE`      | token store path (default `$XDG_STATE_HOME/easyauth-mcp/token.json`) | no          |
| `EASYAUTH_AUTH_HEADER`      | static `Authorization` value; skips the device code flow             | static mode |
| `EASYAUTH_PRINCIPAL_HEADER` | static `x-ms-client-principal-id` value                              | no          |
| `EASYAUTH_ALLOWED_TAGS`     | comma list of allowed tags; empty = all except `EASYAUTH_DENY_TAGS`  | no          |
| `EASYAUTH_DENY_TAGS`        | comma list of tags that never become tools; empty by default         | no          |
| `EASYAUTH_ALLOWED_METHODS`  | comma list of HTTP methods (default `GET`)                           | no          |
| `EASYAUTH_PATH_PREFIX`      | only paths with this prefix (default `/api/`)                        | no          |

`EASYAUTH_DENY_TAGS` is strongly recommended when an API exposes `GET` endpoints
with side effects (background jobs or replication triggers, for example). Because
the default is empty, nothing is hidden unless you configure it.

Run `easyauth-mcp --help` for the matching flags.

Tenant ID, client ID and scope are deployment specific. Get them from the app
registration or from the deployment documentation of the API you connect to.

Configuration is never written to disk. Change the variables in the host
configuration and restart the server.

## Tool filtering

Every operation of the spec becomes a candidate tool, then three filters apply:

1. **Path prefix**: only paths below `EASYAUTH_PATH_PREFIX` (default `/api/`). This
   removes a duplicate `/rest/...` mapping when the API has one.
2. **HTTP method**: only methods in `EASYAUTH_ALLOWED_METHODS` (default `GET`).
3. **Tags**: `EASYAUTH_ALLOWED_TAGS` is an allowlist when set. When it is empty,
   every tag is allowed except the ones in `EASYAUTH_DENY_TAGS`.

`EASYAUTH_DENY_TAGS` is **configurable and empty by default**. That means a `GET`
endpoint that triggers side effects would be exposed unless you configure it. This is a deliberate decision: side-effect tags are
deployment-specific. **Set `EASYAUTH_DENY_TAGS` for any API that has such
endpoints**, e.g. `EASYAUTH_DENY_TAGS=etl,jira-replication`.

Tool names come from `operationId` when it is stable, otherwise from
`METHOD + path` (for example `get_api_workingday_by_employee_sign`). springdoc
suffixes such as `..._1` are treated as artifacts and replaced.

Read-only by default: enabling writes requires both
`EASYAUTH_ALLOWED_METHODS=GET,POST` and an explicit tag allowlist.

## Sign-in

Two modes exist:

- **Device code** (default): `EASYAUTH_TENANT_ID`, `EASYAUTH_CLIENT_ID` and
  `EASYAUTH_SCOPE` are required. The first call to `easyauth_sign_in` starts the flow
  and returns the user code as the tool result; polling continues in the
  background. Once confirmed, calling it again loads the spec and registers the
  real tools via `tools/list_changed`, without restarting the server.
- **Static header**: set `EASYAUTH_AUTH_HEADER` (and optionally
  `EASYAUTH_PRINCIPAL_HEADER`). No login, no token store - useful for a local
  setup.

The token is stored under `$XDG_STATE_HOME/easyauth-mcp/token.json` (fallback
`~/.local/state/easyauth-mcp/token.json`) with mode `0600` and refreshed
automatically. The API itself may not check `exp`, so the server refreshes 60
seconds before expiry itself.

Some deployments protect the OpenAPI document (`/api/doc/api-docs`) as well. When
the anonymous spec fetch returns `401`, the server starts with
`easyauth_sign_in` only and loads the spec after the sign-in.

Against a local backend, a `?login-name=` query parameter on the base URL can
replace the Entra flow: set
`EASYAUTH_BASE_URL='http://localhost:8080?login-name=<user>'`,
`EASYAUTH_OPENAPI='http://localhost:8080/api/doc/api-docs'` and
`EASYAUTH_AUTH_HEADER='Bearer local'`.

## Tool results

- Success returns the response **body** as text. The HTTP status is not part of
  the text; it only decides whether the result is an error. The `Accept` header is
  always `application/json`; the `csv` query parameter is removed from the schemas.
- Some APIs use `404` as a business result (e.g. an empty result set), not a
  failure. It is passed through as content with its status code.
- `IsError` is set only for transport errors, token errors, `5xx`, and a `401`
  that persists after one refresh.
- `401` triggers exactly one refresh and retry. `403` never refreshes.
- Bodies are truncated at 256 KiB with a marker.
- Response schemas are not part of the tool definition; the JSON is returned
  as text.

## Project layout

```
cmd/easyauth-mcp/main.go        MCP server, wiring, tool registration
cmd/easyauth-mcp/config.go      flags and EASYAUTH_* environment variables
cmd/easyauth-mcp/setup.go       easyauth_help and easyauth_sign_in
internal/spec/                  OpenAPI loading, filtering, naming, input schemas
internal/auth/                  device code flow, token store, session
internal/api/                   generic HTTP executor
```

## Releases

Pushing a tag such as `v0.1.0` triggers the release workflow, which runs the
tests and publishes binaries for Linux and macOS (amd64/arm64) and Windows
(amd64) via [GoReleaser](https://goreleaser.com/):

```bash
git tag v0.1.0
git push origin v0.1.0
```

CI runs `make fmt-check`, `make vet`, `make build`, `make test` and a
cross-build on every push and pull request (see `.github/workflows/ci.yaml`).
[golangci-lint](https://golangci-lint.run/) checks the Go code for bugs and
security issues (see `.github/workflows/golangci-lint.yaml` and
`.golangci.yml`).
[zizmor](https://docs.zizmor.sh/) audits the GitHub Actions setup with the
`pedantic` persona (see `.github/workflows/zizmor.yaml`). Dependabot keeps
GitHub Actions and Go modules up to date.

## Development

Common tasks are wrapped by the `Makefile`:

```bash
make check   # fmt-check + vet + test, writes nothing
make build   # build bin/easyauth-mcp
make cover   # tests with a coverage profile
make lint    # golangci-lint run ./... (needs golangci-lint)
make fmt     # gofmt -w .
```

`make check` is what a pull request must pass. The raw commands behind it are
`go vet ./...`, `gofmt -l .` and `go test ./...`; `make lint` runs
golangci-lint as configured in `.golangci.yml`.

Tests run without network access (`httptest` for API clients, and the checked-in
spec at `testdata/openapi-fixture.json`).

## Commit conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
Format:

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

Common types:

| Type       | Purpose                                                 |
|------------|---------------------------------------------------------|
| `feat`     | New feature                                             |
| `fix`      | Bug fix                                                 |
| `docs`     | Documentation only                                      |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test`     | Adding or correcting tests                              |
| `chore`    | Build, tooling, dependencies, ignore files              |

Examples:

```
feat(spec): derive tool names from the path when operationId is unstable
fix(auth): persist the rotated refresh token before using the new token
docs: document the opencode environment key
```

Use the imperative mood, lowercase after the colon, and no trailing period.
Breaking changes are marked with `!` (`feat(api)!: ...`) and a
`BREAKING CHANGE:` footer.

## License

MIT License, Copyright © 2026 HBT GmbH. See [LICENSE](LICENSE).
