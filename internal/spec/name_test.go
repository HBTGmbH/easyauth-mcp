package spec

import "testing"

func TestPathToolName(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   string
	}{
		{"GET", "/api/overtimes/status", "get_api_overtimes_status"},
		{"GET", "/api/workingday/{employeeSign}", "get_api_workingday_by_employee_sign"},
		{"GET", "/api/workingday/.me", "get_api_workingday_me"},
		{"GET", "/api/workingday/.me/{date}", "get_api_workingday_me_by_date"},
		{"GET", "/api/etl/{etl-name}/execute", "get_api_etl_by_etl_name_execute"},
		{"POST", "/api/daily-reports/list", "post_api_daily_reports_list"},
	}
	for _, tc := range cases {
		if got := pathToolName(tc.method, tc.path); got != tc.want {
			t.Errorf("pathToolName(%q, %q) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestBaseToolName(t *testing.T) {
	if got := baseToolName("getOvertimeStatus", "GET", "/api/overtimes/status"); got != "get_overtime_status" {
		t.Errorf("stable operationId = %q, want get_overtime_status", got)
	}
	if got := baseToolName("getAPIStatus", "GET", "/api/status"); got != "get_api_status" {
		t.Errorf("acronym operationId = %q, want get_api_status", got)
	}
	if got := baseToolName("get_api_status", "GET", "/api/status"); got != "get_api_status" {
		t.Errorf("snake operationId = %q, want get_api_status", got)
	}
	if got := baseToolName("getBookings_1", "GET", "/api/bookings"); got != "get_api_bookings" {
		t.Errorf("springdoc operationId = %q, want get_api_bookings", got)
	}
	if got := baseToolName("", "GET", "/api/favorite"); got != "get_api_favorite" {
		t.Errorf("empty operationId = %q, want get_api_favorite", got)
	}
	if got := baseToolName("Get-Bookings", "GET", "/api/bookings"); got != "get_bookings" {
		t.Errorf("hyphenated operationId = %q, want get_bookings", got)
	}
}

func TestNormalizeNameTruncates(t *testing.T) {
	long := ""
	for range 100 {
		long += "a"
	}
	got := normalizeName(long)
	if len(got) != maxToolNameLen {
		t.Errorf("length = %d, want %d", len(got), maxToolNameLen)
	}
}

func TestUniqueNameSuffix(t *testing.T) {
	used := map[string]struct{}{}
	first := uniqueName("same", used)
	used[first] = struct{}{}
	second := uniqueName("same", used)
	used[second] = struct{}{}
	third := uniqueName("same", used)

	if first != "same" || second != "same_2" || third != "same_3" {
		t.Errorf("got %q, %q, %q", first, second, third)
	}
}

func TestUniqueNameRespectsLimit(t *testing.T) {
	base := normalizeName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // 64 chars
	used := map[string]struct{}{base: {}}
	got := uniqueName(base, used)
	if len(got) > maxToolNameLen {
		t.Errorf("collision name %q exceeds %d chars", got, maxToolNameLen)
	}
	if got[len(got)-2:] != "_2" {
		t.Errorf("collision name %q should end in _2", got)
	}
}
