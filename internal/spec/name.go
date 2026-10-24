package spec

import (
	"regexp"
	"strconv"
	"strings"
)

const maxToolNameLen = 64

var (
	springDocSuffixRe = regexp.MustCompile(`_\d+$`)
	nonNameRe         = regexp.MustCompile(`[^a-z0-9_]+`)
	pathParamRe       = regexp.MustCompile(`\{([^}]+)\}`)
)

// baseToolName prefers a stable operationId, otherwise derives the name from
// method and path.
func baseToolName(operationID, method, path string) string {
	if operationID != "" && !springDocSuffixRe.MatchString(operationID) {
		if name := normalizeName(camelToSnake(operationID)); name != "" {
			return name
		}
	}
	return pathToolName(method, path)
}

func pathToolName(method, path string) string {
	var segments []string
	for segment := range strings.SplitSeq(strings.Trim(path, "/"), "/") {
		segment = strings.TrimPrefix(segment, ".")
		if segment == "" {
			continue
		}
		if match := pathParamRe.FindStringSubmatch(segment); match != nil {
			segments = append(segments, "by", camelToSnake(match[1]))
			continue
		}
		segments = append(segments, camelToSnake(segment))
	}

	name := normalizeName(strings.ToLower(method) + "_" + strings.Join(segments, "_"))
	return name
}

// camelToSnake splits camelCase and acronym boundaries and replaces
// separators with underscores. Examples:
//
//	getOvertimeStatus     -> get_overtime_status
//	getAPIStatus          -> get_api_status
//	get_api_status        -> get_api_status (unchanged)
func camelToSnake(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		switch {
		case r == '-' || r == '.' || r == ' ':
			b.WriteByte('_')
		case r >= 'A' && r <= 'Z':
			isUpperRune := func(r rune) bool { return r >= 'A' && r <= 'Z' }
			isLowerRune := func(r rune) bool { return r >= 'a' && r <= 'z' }
			prevLower := i > 0 && isLowerRune(runes[i-1])
			// End of an acronym followed by a new capital word: APIStatus -> API_Status.
			acronymBoundary := i > 0 && i+1 < len(runes) && isUpperRune(runes[i-1]) && isLowerRune(runes[i+1])
			if i > 0 && (prevLower || acronymBoundary) {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizeName lowercases, restricts to [a-z0-9_] and truncates to the limit.
func normalizeName(s string) string {
	name := nonNameRe.ReplaceAllString(strings.ToLower(s), "_")
	name = strings.Trim(name, "_")
	if len(name) > maxToolNameLen {
		name = strings.TrimRight(name[:maxToolNameLen], "_")
	}
	return name
}

// uniqueName appends an incrementing suffix on collision.
func uniqueName(name string, used map[string]struct{}) string {
	if name == "" {
		name = "tool"
	}
	if _, exists := used[name]; !exists {
		return name
	}
	for i := 2; ; i++ {
		suffix := "_" + strconv.Itoa(i)
		candidate := name
		if len(candidate)+len(suffix) > maxToolNameLen {
			candidate = strings.TrimRight(candidate[:maxToolNameLen-len(suffix)], "_")
		}
		candidate += suffix
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
}
