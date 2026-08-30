// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Reproductions for three defects (plus one canonicalization collision) in the
// JCS signing processor, verified against PR #50548 head f61bc9bd05.
//
// Each test is self-contained and drops into the package's own internal test
// package (package signingprocessor), so it can reach the unexported
// marshalJCS / valueToInterface / signingProcessor symbols directly.
//
// The two stack-overflow reproductions (Defect 1 and Defect 2) cannot run in
// the test process itself: a Go "fatal error: stack overflow" is not a panic
// and recover() cannot catch it, so triggering it in-process would kill the
// whole test binary. They use the standard Go self-exec pattern: the test
// re-runs its own binary with a guard env var set, and the parent asserts the
// child died with a stack overflow in the expected frame.
package signingprocessor

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// crashDepthJSONMarshal is well above the measured json.Marshal stack-overflow
// threshold. Measured against Go 1.25.5 on linux/amd64 at PR head f61bc9bd05:
// a nested []any tree overflows the 1 GiB goroutine stack somewhere between
// ~700,000 and ~800,000 levels (run-to-run variable). 2,000,000 crashes every
// time. NOTE: this is lower than the "~1,000,000" figure in the original
// analysis; the real threshold for a slice tree is ~0.7-0.8M.
const crashDepthJSONMarshal = 2_000_000

// crashDepthValueToInterface is above the measured valueToInterface threshold.
// valueToInterface recurses with far fewer frames per level than encoding/json,
// so it survives deeper: measured overflow is between ~2,000,000 and ~3,000,000
// levels. 5,000,000 crashes every time.
const crashDepthValueToInterface = 5_000_000

const crashModeEnv = "SIGNINGPROC_REPRO_CRASH_MODE"

// nestedSliceNative builds a native []any tree of the given depth, the in-memory
// shape json.Marshal walks after valueToInterface flattens an OTLP KeyValueList.
func nestedSliceNative(depth int) any {
	var v any = "leaf"
	for i := 0; i < depth; i++ {
		v = []any{v}
	}
	return v
}

// nestedPcommonSlice builds a depth-deep pcommon.Value slice-of-slice tree
// iteratively (no deep call stack during construction), the crafted OTLP shape
// that valueToInterface walks.
func nestedPcommonSlice(depth int) pcommon.Value {
	root := pcommon.NewValueSlice()
	cur := root
	for i := 0; i < depth; i++ {
		child := cur.Slice().AppendEmpty()
		child.SetEmptySlice()
		cur = child
	}
	return root
}

// runCrashChild re-execs this test binary running only testName, with the crash
// guard env var set to mode, and returns the child's combined output and error.
func runCrashChild(t *testing.T, testName, mode string) (string, error) {
	t.Helper()
	// #nosec G204 -- os.Args[0] is this test binary; args are constant.
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), crashModeEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Defect 1: the depth guard sits DOWNSTREAM of the crash.
//
// marshalJCS calls json.Marshal FIRST (processor.go:263), then the size check,
// then the byte-scan depth guard (processor.go:270-281). A sufficiently nested
// input overflows the stack inside encoding/json before the jcsMaxDepth=128 cap
// is ever consulted, so the guard cannot prevent the crash.
func TestDefect1_JSONMarshalCrashesUpstreamOfDepthGuard(t *testing.T) {
	if os.Getenv(crashModeEnv) == "defect1" {
		// Child: this call overflows the stack inside json.Marshal at
		// processor.go:263, before the depth guard at processor.go:270.
		p := &signingProcessor{}
		_, _ = p.marshalJCS(nestedSliceNative(crashDepthJSONMarshal))
		// If we get here, no crash happened; signal that to the parent.
		//nolint:forbidigo // sentinel for the parent process
		os.Stdout.WriteString("CHILD_RETURNED_NO_CRASH\n")
		return
	}

	// Parent, part A: prove the guard DOES reject when it is actually reached.
	// A depth-200 tree (> jcsMaxDepth 128, far below the crash threshold) is
	// rejected cleanly in-process, no crash.
	p := &signingProcessor{}
	if _, err := p.marshalJCS(nestedSliceNative(200)); err == nil {
		t.Fatal("expected depth-200 input to be rejected by the guard, got nil error")
	} else if !strings.Contains(err.Error(), "nesting depth limit") {
		t.Fatalf("expected nesting-depth-limit error, got: %v", err)
	}

	// Parent, part B: a very deep tree crashes inside json.Marshal, upstream of
	// the guard, even though jcsMaxDepth=128 is present.
	out, err := runCrashChild(t, "TestDefect1_JSONMarshalCrashesUpstreamOfDepthGuard", "defect1")
	if strings.Contains(out, "CHILD_RETURNED_NO_CRASH") {
		t.Fatalf("child returned without crashing; expected a fatal stack overflow.\nchild output:\n%s", out)
	}
	if err == nil {
		t.Fatalf("expected child to die (non-zero exit) from a fatal stack overflow, got nil error.\nchild output:\n%s", out)
	}
	if !strings.Contains(out, "stack overflow") {
		t.Fatalf("expected 'stack overflow' in child output.\nchild output:\n%s", out)
	}
	if !strings.Contains(out, "encoding/json") {
		t.Fatalf("expected the overflow to be inside encoding/json (upstream of the depth guard).\nchild output:\n%s", out)
	}
	t.Logf("Defect 1 reproduced: json.Marshal overflowed the stack upstream of the jcsMaxDepth=128 guard; recover() cannot catch it.")
}

// Defect 2: valueToInterface is a SECOND unbounded recursion.
//
// serializeLogRecord calls valueToInterface (processor.go:244) on every
// attribute BEFORE anything reaches marshalJCS. valueToInterface recurses over
// pcommon Slice/Map values (processor.go:297-309) with no depth argument and no
// cap, so a deeply nested OTLP value overflows the stack on its own.
func TestDefect2_ValueToInterfaceUnboundedRecursion(t *testing.T) {
	if os.Getenv(crashModeEnv) == "defect2" {
		// Child: this overflows the stack inside valueToInterface itself.
		p := &signingProcessor{}
		_ = p.valueToInterface(nestedPcommonSlice(crashDepthValueToInterface))
		//nolint:forbidigo // sentinel for the parent process
		os.Stdout.WriteString("CHILD_RETURNED_NO_CRASH\n")
		return
	}

	out, err := runCrashChild(t, "TestDefect2_ValueToInterfaceUnboundedRecursion", "defect2")
	if strings.Contains(out, "CHILD_RETURNED_NO_CRASH") {
		t.Fatalf("child returned without crashing; expected a fatal stack overflow.\nchild output:\n%s", out)
	}
	if err == nil {
		t.Fatalf("expected child to die from a fatal stack overflow, got nil error.\nchild output:\n%s", out)
	}
	if !strings.Contains(out, "stack overflow") {
		t.Fatalf("expected 'stack overflow' in child output.\nchild output:\n%s", out)
	}
	if !strings.Contains(out, "valueToInterface") {
		t.Fatalf("expected the overflow frame to be valueToInterface.\nchild output:\n%s", out)
	}
	t.Logf("Defect 2 reproduced: valueToInterface recursed without bound and overflowed the stack before json.Marshal was ever called.")
}

// Defect 3: the depth scan counts braces inside JSON string literals.
//
// The guard iterates raw bytes with a bare switch over '{','[','}',']'
// (processor.go:271-281) with no awareness of string literals. json.Marshal
// does not escape { } [ ] inside strings, so an attacker-controlled string value
// moves the depth counter. Two failure directions are shown.
func TestDefect3_DepthScanCountsBracesInsideStrings(t *testing.T) {
	p := &signingProcessor{}

	// (a) OVER-INCLUSIVE (false rejection): a benign record whose true
	// structural depth is 2, but one string attribute value is 200 '{' chars.
	// The scan counts those 200 braces and rejects a completely shallow record.
	overInclusive := map[string]any{
		"attributes": map[string]any{"note": strings.Repeat("{", 200)},
	}
	if _, err := p.marshalJCS(overInclusive); err == nil {
		t.Error("(a) expected the guard to FALSELY reject a shallow record whose string value contains many '{'; got nil error")
	} else if !strings.Contains(err.Error(), "nesting depth limit") {
		t.Errorf("(a) expected a nesting-depth-limit rejection, got: %v", err)
	} else {
		t.Logf("(a) over-inclusive confirmed: true structural depth 2, falsely rejected as too deep: %v", err)
	}

	// (b) UNDER-INCLUSIVE (evasion): a record whose true structural nesting is
	// 302 levels deep (well over jcsMaxDepth=128) but which the guard ACCEPTS,
	// because a sibling string value full of '}' (sorted first, key "a") drives
	// the running counter negative so its running peak never exceeds 128.
	deep := any("leaf")
	for i := 0; i < 300; i++ {
		deep = map[string]any{"n": deep}
	}
	evasion := map[string]any{
		"a": strings.Repeat("}", 400), // masking string, sorts before "b"
		"b": deep,                     // true depth ~302, should be rejected
	}
	out, err := p.marshalJCS(evasion)
	if err != nil {
		t.Errorf("(b) expected the guard to be EVADED (no error) despite true depth ~302 > 128; got error: %v", err)
	} else if len(out) == 0 {
		t.Error("(b) expected non-empty canonical output from the evaded guard")
	} else {
		t.Logf("(b) evasion confirmed: a ~302-level-deep payload (> cap 128) passed the guard and was canonicalized (%d bytes out).", len(out))
	}
}

// Defect 4 (canonicalization collision): gowebpki/jcs v1.0.1 maps distinct
// escaped surrogate sequences to a single U+FFFD, so two distinguishable inputs
// canonicalize to one byte string and therefore take one identical signature.
func TestDefect4_JCSSurrogateCollision(t *testing.T) {
	// Two DISTINCT JSON string literals: two high surrogates vs two low
	// surrogates. gowebpki/jcs collapses each pair to a single U+FFFD.
	inA := []byte(`"\ud800\ud800"`)
	inB := []byte(`"\udfff\udfff"`)
	if string(inA) == string(inB) {
		t.Fatal("test inputs are not distinct")
	}
	outA, errA := jcs.Transform(inA)
	outB, errB := jcs.Transform(inB)
	if errA != nil || errB != nil {
		t.Fatalf("jcs.Transform errored: A=%v B=%v", errA, errB)
	}
	if !strings.EqualFold(hex.EncodeToString(outA), hex.EncodeToString(outB)) {
		t.Fatalf("expected identical canonical bytes; got A=%s B=%s", hex.EncodeToString(outA), hex.EncodeToString(outB))
	}
	t.Logf("Defect 4 reproduced (jcs level): distinct inputs %s and %s both canonicalize to bytes %s (single U+FFFD); they would receive one identical signature.",
		inA, inB, hex.EncodeToString(outA))

	// Processor-reachable variant: json.Marshal (which runs before jcs in
	// marshalJCS) already collapses distinct invalid-UTF-8 byte sequences to
	// U+FFFD, so two distinguishable log bodies collide before jcs is reached.
	s1 := string([]byte{0xed, 0xa0, 0x80}) // invalid UTF-8: encoded high surrogate
	s2 := string([]byte{0xed, 0xbf, 0xbf}) // invalid UTF-8: encoded low surrogate
	if s1 == s2 {
		t.Fatal("byte-level inputs are not distinct")
	}
	r1, _ := json.Marshal(map[string]any{"body": s1})
	r2, _ := json.Marshal(map[string]any{"body": s2})
	if string(r1) != string(r2) {
		t.Fatalf("expected distinct invalid-UTF-8 bodies to collide at json.Marshal; got %s vs %s", r1, r2)
	}
	t.Logf("Defect 4 reproduced (processor-reachable): distinct invalid-UTF-8 bodies both marshal to %s before jcs is reached, colliding to one signature.", r1)
}
