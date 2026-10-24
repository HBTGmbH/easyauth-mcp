package spec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func loadFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "openapi-fixture.json")
	data, err := os.ReadFile(path) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func buildTools(t *testing.T, filter Filter) []Tool {
	t.Helper()
	tools, err := Build(loadFixture(t), filter)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return tools
}

func toolByName(tools []Tool, name string) *Tool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}

func propertyNames(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	return props
}

func requiredList(t *testing.T, schema map[string]any) []string {
	t.Helper()
	raw, ok := schema["required"].([]string)
	if !ok {
		return nil
	}
	return raw
}

func contains(items []string, want string) bool {
	return slices.Contains(items, want)
}

func TestBuildDefaultFilter(t *testing.T) {
	tools := buildTools(t, DefaultFilter())

	seen := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		if _, dup := seen[tool.Name]; dup {
			t.Errorf("duplicate tool name %q", tool.Name)
		}
		seen[tool.Name] = struct{}{}

		if tool.Method != http.MethodGet {
			t.Errorf("tool %q uses non-GET method %s", tool.Name, tool.Method)
		}
		if len(tool.Path) >= 5 && tool.Path[:5] == "/rest" {
			t.Errorf("tool %q points to /rest path %q", tool.Name, tool.Path)
		}
	}

	if toolByName(tools, "get_api_favorite") == nil {
		t.Errorf("expected get_api_favorite in default set")
	}
	if toolByName(tools, "post_api_favorite") != nil {
		t.Errorf("POST tool must not be included")
	}
	// Without a configured deny list, a GET operation is included even if the
	// deployment later marks its tag as side-effecting.
	if toolByName(tools, "get_api_etl_execute_all") == nil {
		t.Errorf("etl GET should be included when no deny list is configured")
	}
}

func TestConfiguredDeniedTagsAreExcluded(t *testing.T) {
	t.Cleanup(func() { SetDeniedTags(nil) })
	SetDeniedTags([]string{"etl", "jira-replication", "auth-service"})

	tools := buildTools(t, DefaultFilter())
	for _, tool := range tools {
		for _, denied := range DeniedTags {
			if toolHasTag(tool, denied) {
				t.Errorf("tool %q carries denied tag %q", tool.Name, denied)
			}
		}
	}
	if toolByName(tools, "get_api_etl_execute_all") != nil {
		t.Errorf("get_api_etl_execute_all must be excluded when its tag is denied")
	}
}

// toolHasTag infers a tag from the fixture paths, because Tool does not expose
// tags.
func toolHasTag(tool Tool, denied string) bool { //nolint:gocritic // hugeParam: a test helper value copy
	switch denied {
	case "etl":
		return strings.Contains(tool.Path, "/etl/")
	case "jira-replication":
		return strings.Contains(tool.Path, "/jira/")
	case "auth-service":
		return strings.Contains(tool.Path, "/auth/")
	}
	return false
}

func TestDenyLogicInline(t *testing.T) {
	inline := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/etl/run": {"get": {"tags": ["etl"], "responses": {"200": {"description": "ok"}}}},
    "/api/plain": {"get": {"tags": ["plain"], "responses": {"200": {"description": "ok"}}}}
  }
}`)

	SetDeniedTags([]string{"etl"})
	t.Cleanup(func() { SetDeniedTags(nil) })

	denied, err := Build(inline, Filter{})
	if err != nil {
		t.Fatalf("Build denied: %v", err)
	}
	if toolByName(denied, "get_api_etl_run") != nil {
		t.Errorf("etl GET must be excluded with empty allowlist")
	}
	if toolByName(denied, "get_api_plain") == nil {
		t.Errorf("plain GET must be present")
	}

	allowed, err := Build(inline, Filter{AllowedTags: []string{"etl"}})
	if err != nil {
		t.Fatalf("Build allowed: %v", err)
	}
	if toolByName(allowed, "get_api_etl_run") == nil {
		t.Errorf("etl GET must be present when explicitly allowed")
	}
}

func TestBuildTagFilter(t *testing.T) {
	filter := Filter{
		AllowedTags:    []string{"favorite", "daily report", "working days", "overtime", "order", "report"},
		AllowedMethods: []string{"GET"},
	}
	tools := buildTools(t, filter)

	if toolByName(tools, "get_api_daily_reports_list") == nil {
		t.Errorf("expected GET daily reports list")
	}
	if toolByName(tools, "post_api_daily_reports_list") != nil {
		t.Errorf("POST daily reports must be excluded")
	}
	if toolByName(tools, "get_api_etl_execute_all") != nil {
		t.Errorf("etl tools must be excluded by tag filter")
	}
	if toolByName(tools, "get_api_favorite") == nil {
		t.Errorf("expected get_api_favorite")
	}
}

func TestDailyReportsListSchema(t *testing.T) {
	tools := buildTools(t, DefaultFilter())
	tool := toolByName(tools, "get_api_daily_reports_list")
	if tool == nil {
		t.Fatal("tool get_api_daily_reports_list not found")
	}

	required := requiredList(t, tool.InputSchema)
	if !contains(required, "refDate") {
		t.Errorf("required = %v, want refDate", required)
	}

	props := propertyNames(t, tool.InputSchema)
	if props == nil {
		t.Fatal("no properties")
	}
	if _, ok := props["days"]; !ok {
		t.Errorf("expected property days, got %v", props)
	}
	if _, ok := props["csv"]; ok {
		t.Errorf("csv property must be removed")
	}
}

func TestReportsExecuteSchema(t *testing.T) {
	tools := buildTools(t, DefaultFilter())
	tool := toolByName(tools, "get_api_reports_execute")
	if tool == nil {
		t.Fatal("tool get_api_reports_execute not found")
	}

	required := requiredList(t, tool.InputSchema)
	if !contains(required, "name") {
		t.Errorf("required = %v, want name", required)
	}

	props := propertyNames(t, tool.InputSchema)
	format, ok := props["format"].(map[string]any)
	if !ok {
		t.Fatalf("format property missing or wrong type: %v", props["format"])
	}
	enum, ok := format["enum"].([]any)
	if !ok || len(enum) != 2 || enum[0] != "json" || enum[1] != "csv" {
		t.Errorf("format enum = %v, want [json csv]", format["enum"])
	}
}

func TestWorkingDayNames(t *testing.T) {
	tools := buildTools(t, DefaultFilter())

	for _, name := range []string{
		"get_api_workingday_by_employee_sign",
		"get_api_workingday_me",
	} {
		if toolByName(tools, name) == nil {
			t.Errorf("expected tool %q", name)
		}
	}

	// A bare {date} segment becomes by_date; the bundled fixture does not
	// contain such a path, so check it through an inline spec.
	spec := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/workingday/{date}": {"get": {"responses": {"200": {"description": "ok"}}}},
    "/api/workingday/{employeeSign}/{date}": {"get": {"responses": {"200": {"description": "ok"}}}}
  }
}`)
	inline, err := Build(spec, DefaultFilter())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, name := range []string{"get_api_workingday_by_date", "get_api_workingday_by_employee_sign_by_date"} {
		if toolByName(inline, name) == nil {
			t.Errorf("expected inline tool %q", name)
		}
	}
}

func TestOperationIDHandling(t *testing.T) {
	tools := buildTools(t, DefaultFilter())
	if toolByName(tools, "get_overtime_status") == nil {
		t.Errorf("expected operationId-based name get_overtime_status")
	}
	if toolByName(tools, "getovertimestatus") != nil {
		t.Errorf("old collapsed name must not exist")
	}
}

func TestSpringDocSuffixFallsBackToPath(t *testing.T) {
	spec := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/bookings": {
      "get": {"operationId": "getBookings_1", "responses": {"200": {"description": "ok"}}}
    }
  }
}`)
	tools, err := Build(spec, DefaultFilter())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "get_api_bookings" {
		t.Errorf("name = %q, want get_api_bookings", tools[0].Name)
	}
}

func TestNameCollisionSuffix(t *testing.T) {
	spec := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/a": {"get": {"operationId": "same", "responses": {"200": {"description": "ok"}}}},
    "/api/b": {"get": {"operationId": "same", "responses": {"200": {"description": "ok"}}}},
    "/api/c": {"get": {"operationId": "same", "responses": {"200": {"description": "ok"}}}}
  }
}`)
	tools, err := Build(spec, DefaultFilter())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := make([]string, 0, len(tools))
	for _, tool := range tools {
		got = append(got, tool.Name)
	}
	want := []string{"same", "same_2", "same_3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tool %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDeprecatedExcluded(t *testing.T) {
	spec := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/old": {"get": {"deprecated": true, "responses": {"200": {"description": "ok"}}}},
    "/api/new": {"get": {"responses": {"200": {"description": "ok"}}}}
  }
}`)
	tools, err := Build(spec, DefaultFilter())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "get_api_new" {
		t.Errorf("got %+v, want only get_api_new", tools)
	}
}

func TestRequestBodyFlattening(t *testing.T) {
	spec := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/things": {
      "post": {
        "parameters": [{"name": "name", "in": "query", "required": true, "schema": {"type": "string"}}],
        "requestBody": {
          "required": true,
          "content": {"application/json": {"schema": {
            "type": "object",
            "required": ["name", "size"],
            "properties": {"name": {"type": "string"}, "size": {"type": "integer"}}
          }}}
        },
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`)
	tools, err := Build(spec, Filter{AllowedMethods: []string{"POST"}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	props := propertyNames(t, tools[0].InputSchema)
	if _, ok := props["name"]; !ok {
		t.Errorf("missing parameter property name")
	}
	if _, ok := props["body_name"]; !ok {
		t.Errorf("body collision should produce body_name, got %v", props)
	}
	if _, ok := props["size"]; !ok {
		t.Errorf("missing body property size")
	}
	required := requiredList(t, tools[0].InputSchema)
	if !contains(required, "name") || !contains(required, "body_name") {
		t.Errorf("required = %v, want name and body_name", required)
	}
}

func TestParameterReferenceResolved(t *testing.T) {
	spec := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/ref/{id}": {
      "get": {
        "parameters": [{"$ref": "#/components/parameters/ID"}],
        "responses": {"200": {"description": "ok"}}
      }
    }
  },
  "components": {
    "parameters": {
      "ID": {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
    }
  }
}`)
	tools, err := Build(spec, DefaultFilter())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if props := propertyNames(t, tools[0].InputSchema); props["id"] == nil {
		t.Errorf("resolved parameter id missing: %v", props)
	}
}

func TestHeaderFiltering(t *testing.T) {
	spec := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/h": {
      "get": {
        "parameters": [
          {"name": "Authorization", "in": "header", "schema": {"type": "string"}},
          {"name": "X-Ms-Client-Principal-Id", "in": "header", "schema": {"type": "string"}},
          {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`)
	tools, err := Build(spec, DefaultFilter())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	props := propertyNames(t, tools[0].InputSchema)
	if _, ok := props["Authorization"]; ok {
		t.Errorf("Authorization header must be skipped")
	}
	if _, ok := props["X-Ms-Client-Principal-Id"]; ok {
		t.Errorf("x-ms-client-principal-id header must be skipped")
	}
	if _, ok := props["X-Tenant"]; !ok {
		t.Errorf("custom header should be kept: %v", props)
	}
}

func TestLoadLocalFile(t *testing.T) {
	data, err := Load(context.Background(), filepath.Join("..", "..", "testdata", "openapi-fixture.json"))
	if err != nil {
		t.Fatalf("Load local: %v", err)
	}
	if !json.Valid(data) {
		t.Errorf("loaded data is not valid JSON")
	}
}

func TestLoadRemote(t *testing.T) {
	data := loadFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	defer server.Close()

	got, err := Load(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Load remote: %v", err)
	}
	if len(got) != len(data) {
		t.Errorf("remote bytes = %d, want %d", len(got), len(data))
	}
}

func TestLoadRemoteError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	if _, err := Load(context.Background(), server.URL); err == nil {
		t.Errorf("expected error for non-2xx response")
	}
}

func TestParamIn(t *testing.T) {
	tools := buildTools(t, DefaultFilter())

	cases := []struct {
		tool string
		want map[string]string
	}{
		{"get_api_daily_reports_list", map[string]string{"refDate": "query", "days": "query"}},
		{"get_api_workingday_by_employee_sign", map[string]string{"employeeSign": "path"}},
		{"get_api_reports_execute", map[string]string{"name": "query", "format": "query"}},
	}
	for _, tc := range cases {
		tool := toolByName(tools, tc.tool)
		if tool == nil {
			t.Errorf("tool %q not found", tc.tool)
			continue
		}
		if len(tool.ParamIn) != len(tc.want) {
			t.Errorf("%s ParamIn = %v, want %v", tc.tool, tool.ParamIn, tc.want)
			continue
		}
		for key, want := range tc.want {
			if got := tool.ParamIn[key]; got != want {
				t.Errorf("%s ParamIn[%q] = %q, want %q", tc.tool, key, got, want)
			}
		}
	}

	daily := toolByName(tools, "get_api_daily_reports_list")
	if daily != nil {
		if _, ok := daily.ParamIn["csv"]; ok {
			t.Errorf("csv must not appear in ParamIn")
		}
	}
}

func TestParamInBody(t *testing.T) {
	tools := buildTools(t, Filter{AllowedMethods: []string{"POST"}, AllowedTags: []string{"daily report"}})
	tool := toolByName(tools, "post_api_daily_reports_list")
	if tool == nil {
		t.Fatal("post_api_daily_reports_list not found")
	}
	for _, name := range []string{"date", "startTime", "breakDuration", "dailyReports"} {
		if got := tool.ParamIn[name]; got != "body" {
			t.Errorf("ParamIn[%q] = %q, want body", name, got)
		}
	}
}

func TestParamInBodyCollision(t *testing.T) {
	inline := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/things": {
      "post": {
        "parameters": [{"name": "name", "in": "query", "schema": {"type": "string"}}],
        "requestBody": {"content": {"application/json": {"schema": {
          "type": "object",
          "properties": {"name": {"type": "string"}, "size": {"type": "integer"}}
        }}}},
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`)
	tools, err := Build(inline, Filter{AllowedMethods: []string{"POST"}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	want := map[string]string{"name": "query", "body_name": "body", "size": "body"}
	if len(tools[0].ParamIn) != len(want) {
		t.Fatalf("ParamIn = %v, want %v", tools[0].ParamIn, want)
	}
	for key, w := range want {
		if got := tools[0].ParamIn[key]; got != w {
			t.Errorf("ParamIn[%q] = %q, want %q", key, got, w)
		}
	}
}

func TestDescriptionTruncatedUTF8(t *testing.T) {
	desc := strings.Repeat("ä", maxDescriptionLen)
	inline := []byte(`{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "paths": {
    "/api/long": {"get": {"summary": "` + desc + `", "responses": {"200": {"description": "ok"}}}}
  }
}`)
	tools, err := Build(inline, DefaultFilter())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if len(tools[0].Description) > maxDescriptionLen {
		t.Errorf("description length = %d, want <= %d", len(tools[0].Description), maxDescriptionLen)
	}
	if !utf8.ValidString(tools[0].Description) {
		t.Errorf("description is not valid UTF-8")
	}
}

func TestLoadRemoteSizeLimit(t *testing.T) {
	old := remoteSpecSizeLimit
	remoteSpecSizeLimit = 16
	t.Cleanup(func() { remoteSpecSizeLimit = old })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 17)))
	}))
	defer server.Close()

	_, err := Load(context.Background(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "spec too large") {
		t.Errorf("expected spec too large error, got %v", err)
	}
}

func TestLoadRemoteWithinSizeLimit(t *testing.T) {
	old := remoteSpecSizeLimit
	remoteSpecSizeLimit = 16
	t.Cleanup(func() { remoteSpecSizeLimit = old })

	data := []byte(strings.Repeat("x", 16))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()

	got, err := Load(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 16 {
		t.Errorf("got %d bytes, want 16", len(got))
	}
}
