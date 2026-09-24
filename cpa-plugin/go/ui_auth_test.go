package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The plugin page reuses the Management Center key from the same-origin
// localStorage. CPA counts every failed management authentication per client IP
// (5 failures -> ~30 min ban, applied even to 127.0.0.1 and even to the correct
// key while banned), so a stale/garbled key plus an unattended poll loop locks
// the operator's own management panel out. These tests pin the contract that
// keeps the page from doing that.

func TestRenderStatusPageInlinesUIAuthModule(t *testing.T) {
	page := renderPageHTML()

	if strings.Contains(page, "/*__EGRESS_UI_AUTH_JS__*/") {
		t.Fatal("ui_auth.js placeholder left unreplaced")
	}
	if !strings.Contains(page, "global.EgressUIAuth = {") {
		t.Fatal("ui_auth.js not inlined into the page")
	}
	authIndex := strings.Index(page, "EgressUIAuth = {")
	panelIndex := strings.Index(page, "const PLUGIN_BASE")
	if authIndex < 0 || panelIndex < 0 {
		t.Fatalf("missing markers: auth=%d panel=%d", authIndex, panelIndex)
	}
	if authIndex > panelIndex {
		t.Fatal("ui_auth.js must be inlined before the page logic that uses it")
	}
}

func TestPageUsesSharedKeyResolverAndStopsPollingOnAuthFailure(t *testing.T) {
	page := renderPageHTML()

	for _, marker := range []string{
		`window.EgressUIAuth.resolveManagementKey`,
		`window.EgressUIAuth.classifyFailure`,
		`window.EgressUIAuth.pollDecision`,
		`window.EgressUIAuth.AUTO_REFRESH_MS`,
		`window.EgressUIAuth.HIDDEN_RECHECK_MS`,
		`function blockAutoRefresh`,
		`function applyFailurePolicy`,
		`function startAutoRefresh`,
		`clearTimeout(state.autoTimer)`,
		`if (authBlocked) return;`,
		`if (fromUser) { authBlocked = null; failureSeq = 0; }`,
		`$('refresh-button').addEventListener('click', () => startAutoRefresh(true))`,
	} {
		if !strings.Contains(page, marker) {
			t.Fatalf("page missing marker %q", marker)
		}
	}

	// The unbounded 15s interval and the guessed authToken key are the two
	// habits that turned a stale key into repeated IP bans.
	if strings.Contains(page, "setInterval") {
		t.Fatal("page must not use an unbounded setInterval poll loop")
	}
	if strings.Contains(pageTemplate, "authToken") {
		t.Fatal("page template must not read the guessed authToken storage key")
	}
	if strings.Contains(page, "'authToken'") || strings.Contains(page, `"authToken"`) {
		t.Fatal("page must not resolve the guessed authToken storage key")
	}
	if !strings.Contains(page, "AUTH_STORAGE_KEYS: AUTH_STORAGE_KEYS") {
		t.Fatal("inlined module must export the storage key allow-list")
	}
	// Auth failures must abort the request pair before the second call.
	if strings.Contains(page, "Promise.all") {
		t.Fatal("page must serialize /quality-guard then /nodes so an auth failure costs a single attempt")
	}
	if !strings.Contains(page, `const status = await api('/quality-guard');`) {
		t.Fatal("first request must be the single auth validation call")
	}
}

// The page ships as one inline script; a syntax error there would silently
// break the panel with no server-side signal. Render it and let node parse it.
func TestRenderedPageScriptParses(t *testing.T) {
	nodePath, errLookup := exec.LookPath("node")
	if errLookup != nil {
		t.Skipf("node not available to parse the page script: %v", errLookup)
	}
	page := renderPageHTML()
	openIndex := strings.Index(page, "<script>")
	closeIndex := strings.LastIndex(page, "</script>")
	if openIndex < 0 || closeIndex <= openIndex {
		t.Fatalf("inline script block not found: open=%d close=%d", openIndex, closeIndex)
	}
	script := page[openIndex+len("<script>") : closeIndex]

	target := filepath.Join(t.TempDir(), "page.js")
	if errWrite := os.WriteFile(target, []byte(script), 0o600); errWrite != nil {
		t.Fatalf("write page script: %v", errWrite)
	}
	out, errRun := exec.Command(nodePath, "--check", target).CombinedOutput()
	if errRun != nil {
		t.Fatalf("page script does not parse: %v\n%s", errRun, out)
	}
}

func TestUIAuthBehaviourHarness(t *testing.T) {
	nodePath, errLookup := exec.LookPath("node")
	if errLookup != nil {
		t.Skipf("node not available for ui_auth behaviour harness: %v", errLookup)
	}
	cmd := exec.Command(nodePath, "ui_auth_harness.mjs")
	cmd.Dir = "."
	out, errRun := cmd.CombinedOutput()
	if errRun != nil {
		t.Fatalf("ui_auth behaviour harness failed: %v\n%s", errRun, out)
	}
	output := string(out)
	if strings.Contains(output, "not ok -") {
		t.Fatalf("ui_auth behaviour harness reported failures:\n%s", output)
	}
	if !strings.Contains(output, "all ui_auth behaviour checks passed") {
		t.Fatalf("ui_auth behaviour harness did not complete:\n%s", output)
	}
}
