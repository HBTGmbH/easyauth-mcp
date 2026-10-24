package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HBTGmbH/easyauth-mcp/internal/auth"
	"github.com/HBTGmbH/easyauth-mcp/internal/spec"
)

// helpToolName is exposed when the server cannot build the real tools. It is
// read-only: configuration comes exclusively from flags and environment
// variables.
const helpToolName = "easyauth_help"

// registerHelpTool exposes a tool that reports why the server is not fully
// operational. It keeps tools/list valid and gives every tools/call a readable
// answer instead of a dropped connection.
func registerHelpTool(server *mcp.Server, s *settings, cause error) {
	server.AddTool(&mcp.Tool{
		Name:        helpToolName,
		Description: "Explain why easyauth-mcp is not ready and which configuration is missing. Only exposed when the server cannot build the API tools.",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return errorResult(diagnosis(s, cause)), nil
	})
}

// diagnosis lists the environment variables the process actually saw and the
// concrete cause. Only variable presence is reported, never values.
func diagnosis(s *settings, cause error) string {
	var lines []string
	lines = append(lines, "easyauth-mcp is not ready.")
	if cause != nil {
		lines = append(lines, cause.Error())
	}
	lines = append(lines, "Required: "+presence("EASYAUTH_BASE_URL", "EASYAUTH_OPENAPI"))
	if s.AuthHeader == "" {
		lines = append(lines, "For sign-in: "+presence("EASYAUTH_TENANT_ID", "EASYAUTH_CLIENT_ID", "EASYAUTH_SCOPE"))
	} else {
		lines = append(lines, "Using the static EASYAUTH_AUTH_HEADER; no sign-in needed.")
	}
	return strings.Join(lines, "\n")
}

func presence(names ...string) string {
	var set, unset []string
	for _, name := range names {
		if os.Getenv(name) != "" {
			set = append(set, name)
		} else {
			unset = append(unset, name)
		}
	}
	var parts []string
	if len(set) > 0 {
		parts = append(parts, "set: "+strings.Join(set, ", "))
	}
	if len(unset) > 0 {
		parts = append(parts, "missing: "+strings.Join(unset, ", "))
	}
	return strings.Join(parts, "; ")
}

// signInToolName is exposed when the OpenAPI spec itself needs authentication.
const signInToolName = "easyauth_sign_in"

// registerSignInTool adds a tool that completes the device sign-in and then
// loads the spec. Installing the tools on the running server notifies the
// client through tools/list_changed, so no restart is needed.
func registerSignInTool(server *mcp.Server, reg *registrar) {
	server.AddTool(&mcp.Tool{
		Name:        signInToolName,
		Description: "Sign in to the API. Call it, confirm the returned device code in a browser, then call it again; the API tools become available immediately.",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		s := reg.settings
		session, err := buildSession(s, reg.stderr)
		if err != nil {
			return errorResult("easyauth-mcp is not configured for authentication: " + err.Error()), nil //nolint:nilerr // the error is reported inside the tool result
		}

		tok, err := session.Peek(ctx)
		if err != nil {
			tok, err = session.Token(ctx)
			if err != nil {
				if required, ok := errors.AsType[*auth.ErrLoginRequired](err); ok {
					return errorResult(signInPrompt(required.Login)), nil
				}
				return errorResult("sign-in failed: " + err.Error()), nil
			}
		}

		data, err := spec.LoadWithHeader(ctx, s.OpenAPI, tok.Header())
		if err != nil {
			return errorResult("signed in, but loading the OpenAPI spec failed: " + err.Error()), nil //nolint:nilerr // the error is reported inside the tool result
		}
		tools, err := buildTools(data, s)
		if err != nil {
			return errorResult("signed in, but building tools failed: " + err.Error()), nil //nolint:nilerr // the error is reported inside the tool result
		}
		if len(tools) == 0 {
			return errorResult("Signed in, but the OpenAPI spec produced no tools with the current filter."), nil
		}
		if err := reg.install(ctx, tools); err != nil {
			return errorResult("Signed in, but installing the tools failed: " + err.Error()), nil //nolint:nilerr // the error is reported inside the tool result
		}
		return textResult(fmt.Sprintf(
			"Signed in. %d API tool(s) are now available and already registered (%s). "+
				"Call them directly; no restart is needed.",
			len(tools), toolNameSample(tools, 5))), nil
	})
}

// signInPrompt asks the user to confirm the device code. It stays inside the
// tool result so the agent can show it.
func signInPrompt(login auth.DeviceLogin) string {
	if login.VerificationURI == "" || login.UserCode == "" {
		return "Sign-in required, but no device code was returned. Check the authentication settings."
	}
	return fmt.Sprintf(
		"Sign-in required. Open %s and enter the code %s, then call %s again. "+
			"The API tools appear automatically once the sign-in is complete.",
		login.VerificationURI, login.UserCode, signInToolName)
}

// toolNameSample lists up to n tool names for a message, sorted for stable
// output, and marks omissions with an ellipsis.
func toolNameSample(tools []spec.Tool, n int) string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	if len(names) > n {
		return strings.Join(names[:n], ", ") + ", …"
	}
	return strings.Join(names, ", ")
}
