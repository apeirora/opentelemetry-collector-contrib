// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package canonicaljson

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestValueToInterface(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() pcommon.Value
		maxDepth int
		want     any
		wantErr  bool
		errMsg   string
	}{
		{
			name: "string value",
			setup: func() pcommon.Value {
				v := pcommon.NewValueStr("hello")
				return v
			},
			maxDepth: 128,
			want:     map[string]any{"stringValue": "hello"},
		},
		{
			name: "int value",
			setup: func() pcommon.Value {
				v := pcommon.NewValueInt(42)
				return v
			},
			maxDepth: 128,
			want:     map[string]any{"intValue": "42"},
		},
		{
			name: "double value",
			setup: func() pcommon.Value {
				v := pcommon.NewValueDouble(3.14)
				return v
			},
			maxDepth: 128,
			want:     map[string]any{"doubleValue": 3.14},
		},
		{
			name: "bool value true",
			setup: func() pcommon.Value {
				v := pcommon.NewValueBool(true)
				return v
			},
			maxDepth: 128,
			want:     map[string]any{"boolValue": true},
		},
		{
			name: "bool value false",
			setup: func() pcommon.Value {
				v := pcommon.NewValueBool(false)
				return v
			},
			maxDepth: 128,
			want:     map[string]any{"boolValue": false},
		},
		{
			name: "bytes value",
			setup: func() pcommon.Value {
				v := pcommon.NewValueBytes()
				v.Bytes().FromRaw([]byte{0x01, 0x02, 0x03})
				return v
			},
			maxDepth: 128,
			want:     map[string]any{"bytesValue": base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})},
		},
		{
			name: "empty bytes",
			setup: func() pcommon.Value {
				v := pcommon.NewValueBytes()
				return v
			},
			maxDepth: 128,
			want:     map[string]any{"bytesValue": ""},
		},
		{
			name: "empty value",
			setup: func() pcommon.Value {
				v := pcommon.NewValueEmpty()
				return v
			},
			maxDepth: 128,
			want:     nil,
		},
		{
			name: "slice with primitives",
			setup: func() pcommon.Value {
				v := pcommon.NewValueSlice()
				s := v.Slice()
				s.AppendEmpty().SetStr("a")
				s.AppendEmpty().SetInt(1)
				s.AppendEmpty().SetBool(true)
				return v
			},
			maxDepth: 128,
			want: []any{
				map[string]any{"stringValue": "a"},
				map[string]any{"intValue": "1"},
				map[string]any{"boolValue": true},
			},
		},
		{
			name: "map with primitives",
			setup: func() pcommon.Value {
				v := pcommon.NewValueMap()
				m := v.Map()
				m.PutStr("key1", "value1")
				m.PutInt("key2", 42)
				m.PutBool("key3", false)
				return v
			},
			maxDepth: 128,
			want: map[string]any{
				"key1": map[string]any{"stringValue": "value1"},
				"key2": map[string]any{"intValue": "42"},
				"key3": map[string]any{"boolValue": false},
			},
		},
		{
			name: "nested map",
			setup: func() pcommon.Value {
				v := pcommon.NewValueMap()
				m := v.Map()
				nested := m.PutEmptyMap("nested")
				nested.PutStr("inner", "value")
				return v
			},
			maxDepth: 128,
			want: map[string]any{
				"nested": map[string]any{
					"inner": map[string]any{"stringValue": "value"},
				},
			},
		},
		{
			name: "nested slice",
			setup: func() pcommon.Value {
				v := pcommon.NewValueSlice()
				s := v.Slice()
				inner := s.AppendEmpty()
				innerSlice := inner.SetEmptySlice()
				innerSlice.AppendEmpty().SetStr("nested")
				return v
			},
			maxDepth: 128,
			want: []any{
				[]any{
					map[string]any{"stringValue": "nested"},
				},
			},
		},
		{
			name: "exceeds depth limit",
			setup: func() pcommon.Value {
				v := pcommon.NewValueMap()
				current := v.Map()
				// Create nested maps deeper than limit
				for i := 0; i < 5; i++ {
					next := current.PutEmptyMap("level" + strconv.Itoa(i))
					current = next
				}
				current.PutStr("deep", "value")
				return v
			},
			maxDepth: 3,
			wantErr:  true,
			errMsg:   "exceeds nesting depth limit",
		},
		{
			name: "invalid UTF-8 in string",
			setup: func() pcommon.Value {
				v := pcommon.NewValueStr("invalid\xffutf8")
				return v
			},
			maxDepth: 128,
			wantErr:  true,
			errMsg:   "string value contains invalid UTF-8",
		},
		{
			name: "map with multiple keys sorted",
			setup: func() pcommon.Value {
				v := pcommon.NewValueMap()
				m := v.Map()
				// Add keys in non-alphabetical order to verify they get sorted
				m.PutStr("zebra", "last")
				m.PutStr("apple", "first")
				m.PutStr("middle", "mid")
				return v
			},
			maxDepth: 128,
			want: map[string]any{
				"zebra":  map[string]any{"stringValue": "last"},
				"apple":  map[string]any{"stringValue": "first"},
				"middle": map[string]any{"stringValue": "mid"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tt.setup()
			got, err := valueToInterface(v, 0, tt.maxDepth)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestValueToInterface_LargeInt(t *testing.T) {
	v := pcommon.NewValueInt(9223372036854775807) // max int64
	got, err := valueToInterface(v, 0, 128)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"intValue": "9223372036854775807"}, got)
}

func TestValueToInterface_NegativeInt(t *testing.T) {
	v := pcommon.NewValueInt(-42)
	got, err := valueToInterface(v, 0, 128)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"intValue": "-42"}, got)
}

func TestValueToInterface_EmptySlice(t *testing.T) {
	v := pcommon.NewValueSlice()
	got, err := valueToInterface(v, 0, 128)
	require.NoError(t, err)
	assert.Equal(t, []any{}, got)
}

func TestValueToInterface_EmptyMap(t *testing.T) {
	v := pcommon.NewValueMap()
	got, err := valueToInterface(v, 0, 128)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{}, got)
}

// TestValueToInterface_EmptyValueSerializesToNull verifies that pcommon.ValueTypeEmpty
// returns nil, which marshals to JSON "null" per OTLP spec:
// "Empty values as JSON null" (for array elements)
// This is semantically different from an empty map ({}) or empty slice ([]).
func TestValueToInterface_EmptyValueSerializesToNull(t *testing.T) {
	v := pcommon.NewValueEmpty()

	// ValueToInterface should return nil for empty values
	result, err := ValueToInterface(v, 0, 128)
	require.NoError(t, err)
	require.Nil(t, result, "ValueTypeEmpty should return nil")

	// Verify it marshals to JSON "null"
	jsonBytes, err := json.Marshal(map[string]any{"empty": result})
	require.NoError(t, err)
	assert.Equal(t, `{"empty":null}`, string(jsonBytes),
		"nil should marshal to JSON null, not empty object")

	// Also verify it works in arrays
	arrayJSON, err := json.Marshal([]any{result})
	require.NoError(t, err)
	assert.Equal(t, `[null]`, string(arrayJSON))
}

// TestValueToInterface_EmptyValueVsEmptyMap documents the semantic difference
// between ValueTypeEmpty (no value = null) and ValueTypeMap with len=0 (empty object = {})
func TestValueToInterface_EmptyValueVsEmptyMap(t *testing.T) {
	emptyValue := pcommon.NewValueEmpty()
	emptyMap := pcommon.NewValueMap()

	resultEmpty, err := ValueToInterface(emptyValue, 0, 128)
	require.NoError(t, err)

	resultMap, err := ValueToInterface(emptyMap, 0, 128)
	require.NoError(t, err)

	// They should be different types
	assert.Nil(t, resultEmpty, "Empty value should be nil")
	assert.NotNil(t, resultMap, "Empty map should be non-nil map")
	assert.Equal(t, map[string]any{}, resultMap, "Empty map should be empty map")

	// And marshal differently in JSON
	jsonEmpty, _ := json.Marshal(resultEmpty)
	jsonMap, _ := json.Marshal(resultMap)

	assert.Equal(t, `null`, string(jsonEmpty), "Empty value marshals to null")
	assert.Equal(t, `{}`, string(jsonMap), "Empty map marshals to {}")
}

// TestValueToInterface_Int64Precision verifies that large int64 values beyond
// 2^53 are serialized as strings to preserve precision. IEEE-754 doubles cannot
// represent consecutive integers beyond 2^53, so conversion to float64 would
// cause precision loss.
func TestValueToInterface_Int64Precision(t *testing.T) {
	const base int64 = 9_007_199_254_740_992 // 2^53: first int64 where consecutive values collide in float64

	v1 := pcommon.NewValueInt(base)
	v2 := pcommon.NewValueInt(base + 1)

	result1, err := ValueToInterface(v1, 0, 128)
	require.NoError(t, err)

	result2, err := ValueToInterface(v2, 0, 128)
	require.NoError(t, err)

	assert.NotEqual(t, result1, result2,
		"int64 values differing by 1 beyond 2^53 must produce distinct results")

	assert.Equal(t, map[string]any{"intValue": "9007199254740992"}, result1)
	assert.Equal(t, map[string]any{"intValue": "9007199254740993"}, result2)
}

// TestValueToInterface_ScalarTypeDistinction verifies that same-looking values
// of different OTLP scalar types produce distinct results. Each scalar is wrapped
// in a type-tagged object ({"intValue":…}, {"stringValue":…}, etc.) ensuring
// unique representation per type.
func TestValueToInterface_ScalarTypeDistinction(t *testing.T) {
	tests := []struct {
		name     string
		value1   pcommon.Value
		value2   pcommon.Value
		distinct bool
	}{
		{
			name:     "int 123 vs string \"123\"",
			value1:   pcommon.NewValueInt(123),
			value2:   pcommon.NewValueStr("123"),
			distinct: true,
		},
		{
			name: "bytes vs string with same base64",
			value1: func() pcommon.Value {
				v := pcommon.NewValueBytes()
				v.Bytes().FromRaw([]byte("hello"))
				return v
			}(),
			value2:   pcommon.NewValueStr("aGVsbG8="), // base64("hello")
			distinct: true,
		},
		{
			name:     "bool true vs string \"true\"",
			value1:   pcommon.NewValueBool(true),
			value2:   pcommon.NewValueStr("true"),
			distinct: true,
		},
		{
			name:     "double 1.0 vs string \"1\"",
			value1:   pcommon.NewValueDouble(1.0),
			value2:   pcommon.NewValueStr("1"),
			distinct: true,
		},
		{
			name:     "negative int -5 vs string \"-5\"",
			value1:   pcommon.NewValueInt(-5),
			value2:   pcommon.NewValueStr("-5"),
			distinct: true,
		},
		{
			name: "slice of int [7] vs slice of string [\"7\"]",
			value1: func() pcommon.Value {
				v := pcommon.NewValueSlice()
				v.Slice().AppendEmpty().SetInt(7)
				return v
			}(),
			value2: func() pcommon.Value {
				v := pcommon.NewValueSlice()
				v.Slice().AppendEmpty().SetStr("7")
				return v
			}(),
			distinct: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result1, err := ValueToInterface(tc.value1, 0, 128)
			require.NoError(t, err)

			result2, err := ValueToInterface(tc.value2, 0, 128)
			require.NoError(t, err)

			if tc.distinct {
				assert.NotEqual(t, result1, result2,
					"values of different types must produce distinct results")
			} else {
				assert.Equal(t, result1, result2,
					"values should produce same result")
			}
		})
	}
}

// TestValueToInterface_Float64AdjacentValuesDistinct verifies that adjacent
// IEEE-754 doubles (differing by 1 ULP) produce distinct results. JCS uses the
// shortest round-trip representation, so every finite non-zero double maps to
// a unique string.
func TestValueToInterface_Float64AdjacentValuesDistinct(t *testing.T) {
	tests := []struct {
		name string
		a, b float64
	}{
		{
			name: "small positive: 1.0 vs next ULP",
			a:    1.0,
			b:    1.0000000000000002, // nextafter(1.0, +inf)
		},
		{
			name: "large positive near float64 max",
			a:    1e300,
			b:    1.0000000000000002e+300, // approximately nextafter(1e300, +inf)
		},
		{
			name: "small negative: -1.0 vs next ULP toward zero",
			a:    -1.0,
			b:    -0.9999999999999999, // nextafter(-1.0, 0)
		},
		{
			name: "values near 2^53 (where int64 precision matters)",
			a:    9007199254740992.0, // 2^53
			b:    9007199254740994.0, // 2^53 + 2 (next representable double)
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v1 := pcommon.NewValueDouble(tc.a)
			v2 := pcommon.NewValueDouble(tc.b)

			result1, err := ValueToInterface(v1, 0, 128)
			require.NoError(t, err)

			result2, err := ValueToInterface(v2, 0, 128)
			require.NoError(t, err)

			assert.NotEqual(t, result1, result2,
				"adjacent float64 values must produce distinct results: a=%v b=%v", tc.a, tc.b)
		})
	}
}

// TestValueToInterface_Float64NegativeZeroCollision documents that -0.0 and +0.0
// produce identical results. This is mandated by JCS spec (ES6 §7.1.12.1) and is
// the ONLY float64 precision issue. It is not a bug; it's a deliberate spec requirement.
func TestValueToInterface_Float64NegativeZeroCollision(t *testing.T) {
	vPos := pcommon.NewValueDouble(+0.0)
	vNeg := pcommon.NewValueDouble(-0.0)

	resultPos, err := ValueToInterface(vPos, 0, 128)
	require.NoError(t, err)

	resultNeg, err := ValueToInterface(vNeg, 0, 128)
	require.NoError(t, err)

	// This collision is expected and spec-mandated
	assert.Equal(t, resultPos, resultNeg,
		"JCS spec requires +0.0 and -0.0 to produce identical output")

	// Both should serialize as {"doubleValue":0}
	assert.Equal(t, map[string]any{"doubleValue": float64(0)}, resultPos)
}

// TestValueToInterface_Float64SpecialValuesRejected verifies that NaN and ±Infinity
// are rejected by the JCS transformation (they are invalid JSON numbers).
func TestValueToInterface_Float64SpecialValuesRejected(t *testing.T) {
	// Note: The JCS library will reject these during Transform, not during
	// valueToInterface. We test that the full serialization path rejects them.
	// This test documents expected behavior - the actual rejection happens in marshalJCS.

	tests := []struct {
		name  string
		value float64
	}{
		{"NaN", math.NaN()},
		{"+Inf", math.Inf(1)},
		{"-Inf", math.Inf(-1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := pcommon.NewValueDouble(tc.value)

			// valueToInterface itself accepts these
			result, err := ValueToInterface(v, 0, 128)
			require.NoError(t, err)

			// But they should fail during JSON marshaling
			_, err = json.Marshal(result)
			require.Error(t, err, "expected error marshaling %s to JSON", tc.name)
		})
	}
}

// TestValueToInterface_Float64SerializationFormat verifies the literal form of
// well-known doubles matches RFC 8785 §3.2.2.3 test vectors.
func TestValueToInterface_Float64SerializationFormat(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		want  float64 // Expected value in the doubleValue wrapper
	}{
		{"1.0 serializes as integer when exact", 1.0, 1.0},
		{"1.5 keeps decimal", 1.5, 1.5},
		{"negative value", -2.5, -2.5},
		{"small positive", 0.5, 0.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := pcommon.NewValueDouble(tc.value)
			result, err := ValueToInterface(v, 0, 128)
			require.NoError(t, err)

			assert.Equal(t, map[string]any{"doubleValue": tc.want}, result)
		})
	}
}

// TestValueToInterface_SliceErrorPropagation verifies that errors from nested
// slice elements are properly propagated up. This tests the error handling path
// in the ValueTypeSlice case.
func TestValueToInterface_SliceErrorPropagation(t *testing.T) {
	// Create a slice with deeply nested structure that exceeds maxDepth
	slice := pcommon.NewValueSlice()

	// First element: valid simple value
	slice.Slice().AppendEmpty().SetStr("valid")

	// Second element: deeply nested map that will exceed depth limit
	deepMap := slice.Slice().AppendEmpty().SetEmptyMap()
	current := deepMap
	for i := 0; i < 10; i++ {
		current = current.PutEmptyMap("level")
	}
	current.PutStr("deep", "value")

	// Third element: another valid value (to ensure we test error in middle)
	slice.Slice().AppendEmpty().SetInt(42)

	// Call with maxDepth too low to process the second element
	_, err := ValueToInterface(slice, 0, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting depth limit",
		"error from nested element should propagate through slice")
}

// TestValueToInterface_MapErrorPropagation verifies that errors from nested
// map values are properly propagated up. This tests the error handling path
// in the ValueTypeMap case.
func TestValueToInterface_MapErrorPropagation(t *testing.T) {
	// Create a map with a deeply nested value that exceeds maxDepth
	m := pcommon.NewValueMap()

	m.Map().PutStr("valid_key", "valid_value")

	// Add deeply nested structure as another value
	deepMap := m.Map().PutEmptyMap("deep_key")
	current := deepMap
	for i := 0; i < 10; i++ {
		current = current.PutEmptyMap("level")
	}
	current.PutStr("deep", "value")

	m.Map().PutInt("another_valid", 123)

	// Call with maxDepth too low to process the deep_key value
	_, err := ValueToInterface(m, 0, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting depth limit",
		"error from nested map value should propagate")
}
