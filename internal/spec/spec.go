// Package spec turns an OpenAPI 3 document into MCP tool definitions.
package spec

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	defaultPathPrefix = "/api/"
	maxDescriptionLen = 2000
	maxRemoteSpecSize = 10 << 20 // 10 MiB
)

// DeniedTags lists tags that must never become tools, regardless of the
// method filter. API-specific deployments fill this from their configuration,
// because some APIs trigger side effects with GET.
//
// Empty by default: filtering by HTTP method is the generic baseline, and every
// deployment knows its own side-effect tags better than this package does.
var DeniedTags []string

// SetDeniedTags replaces the deny list. Intended for wiring the configuration.
func SetDeniedTags(tags []string) {
	DeniedTags = tags
}

// remoteSpecSizeLimit is the effective remote download limit. Variable so
// tests can lower it.
var remoteSpecSizeLimit = maxRemoteSpecSize

// ErrUnauthorized reports that the spec document itself needs authentication.
// Callers use it to offer a sign-in instead of a generic configuration hint.
type ErrUnauthorized struct {
	Location string
	Status   string
}

func (e *ErrUnauthorized) Error() string {
	return fmt.Sprintf("fetch spec %q: unexpected status %s", e.Location, e.Status)
}

// Filter selects which OpenAPI operations become MCP tools.
type Filter struct {
	PathPrefix string // default "/api/"
	// AllowedTags is an allowlist. Empty means "all except DeniedTags".
	// A non-empty list is authoritative: only matching tags are allowed, even
	// if they also appear in DeniedTags.
	AllowedTags    []string
	AllowedMethods []string // default ["GET"], case-insensitive
}

// Tool is a single MCP tool derived from one OpenAPI operation.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	// ParamIn maps each InputSchema property name to its origin:
	// "path", "query", "header" or "body".
	ParamIn     map[string]string
	Method      string
	Path        string
	OperationID string
}

// DefaultFilter restricts tools to GET operations below /api/. Operations
// tagged with any DeniedTags (etl, jira-replication, auth-service) are
// excluded because AllowedTags is empty.
func DefaultFilter() Filter {
	return Filter{
		PathPrefix:     defaultPathPrefix,
		AllowedMethods: []string{http.MethodGet},
	}
}

// Load reads an OpenAPI document from a local file or an http(s) URL.
func Load(ctx context.Context, location string) ([]byte, error) {
	return LoadWithHeader(ctx, location, nil)
}

// LoadWithHeader is Load with extra request headers, used to fetch a spec that
// itself requires authentication. Headers are only applied to http(s) URLs.
func LoadWithHeader(ctx context.Context, location string, header http.Header) ([]byte, error) {
	if u, err := url.Parse(location); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return loadRemote(ctx, location, header)
	}
	return loadFile(location)
}

func loadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read spec file %q: %w", path, err)
	}
	return data, nil
}

func loadRemote(ctx context.Context, location string, header http.Header) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("fetch spec %q: %w", location, err)
	}
	req.Header.Set("Accept", "application/json")
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch spec %q: %w", location, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &ErrUnauthorized{Location: location, Status: resp.Status}
		}
		return nil, fmt.Errorf("fetch spec %q: unexpected status %s", location, resp.Status)
	}

	// Read one byte past the limit to detect oversized documents.
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(remoteSpecSizeLimit)+1))
	if err != nil {
		return nil, fmt.Errorf("read spec %q: %w", location, err)
	}
	if len(data) > remoteSpecSizeLimit {
		return nil, fmt.Errorf("fetch spec %q: spec too large (limit %d bytes)", location, remoteSpecSizeLimit)
	}
	return data, nil
}

// Build parses an OpenAPI 3 document and derives the MCP tools matching filter.
// The document is only parsed, never validated. External $refs are rejected.
func Build(data []byte, filter Filter) ([]Tool, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false

	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("parse openapi document: %w", err)
	}

	filter = normalizeFilter(filter)

	if doc.Paths == nil {
		return nil, nil
	}

	var tools []Tool
	usedNames := make(map[string]struct{})

	for _, path := range doc.Paths.InMatchingOrder() {
		if !strings.HasPrefix(path, filter.PathPrefix) {
			continue
		}
		pathItem := doc.Paths.Value(path)
		if pathItem == nil {
			continue
		}

		operations := pathItem.Operations()
		for _, method := range slices.Sorted(maps.Keys(operations)) {
			operation := operations[method]
			if operation == nil || operation.Deprecated {
				continue
			}
			if !methodAllowed(method, filter.AllowedMethods) {
				continue
			}
			if !tagsAllowed(operation.Tags, filter.AllowedTags) {
				continue
			}

			name := uniqueName(baseToolName(operation.OperationID, method, path), usedNames)
			usedNames[name] = struct{}{}

			schema, paramIn := buildInputSchema(operation, pathItem)

			tools = append(tools, Tool{
				Name:        name,
				Description: buildDescription(operation, method, path),
				InputSchema: schema,
				ParamIn:     paramIn,
				Method:      method,
				Path:        path,
				OperationID: operation.OperationID,
			})
		}
	}

	return tools, nil
}

func normalizeFilter(filter Filter) Filter {
	if filter.PathPrefix == "" {
		filter.PathPrefix = defaultPathPrefix
	}
	if len(filter.AllowedMethods) == 0 {
		filter.AllowedMethods = []string{http.MethodGet}
	}
	return filter
}

func methodAllowed(method string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(candidate, method) {
			return true
		}
	}
	return false
}

// tagsAllowed applies the allow/deny logic: a non-empty allowlist is
// authoritative; otherwise all tags are allowed except DeniedTags.
func tagsAllowed(tags, allowed []string) bool {
	if len(allowed) == 0 {
		for _, tag := range tags {
			if slices.Contains(DeniedTags, tag) {
				return false
			}
		}
		return true
	}
	for _, tag := range tags {
		if slices.Contains(allowed, tag) {
			return true
		}
	}
	return false
}

func buildDescription(operation *openapi3.Operation, method, path string) string {
	parts := make([]string, 0, 3)
	if summary := strings.TrimSpace(operation.Summary); summary != "" {
		parts = append(parts, summary)
	}
	if desc := strings.TrimSpace(operation.Description); desc != "" && desc != strings.TrimSpace(operation.Summary) {
		parts = append(parts, desc)
	}
	parts = append(parts, method+" "+path)

	return truncateUTF8(strings.Join(parts, "\n\n"), maxDescriptionLen)
}

// truncateUTF8 cuts s to at most max bytes without splitting a UTF-8 rune.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && s[cut]&0xC0 == 0x80 { // back off continuation bytes
		cut--
	}
	return s[:cut]
}
