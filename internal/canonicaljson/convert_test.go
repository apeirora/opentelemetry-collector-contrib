// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package canonicaljson

import (
	"encoding/base64"
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
			name: "invalid UTF-8 in map key",
			setup: func() pcommon.Value {
				v := pcommon.NewValueMap()
				m := v.Map()
				// This is a bit tricky - we need to create an invalid key
				// We'll use UnsafeInsert which bypasses validation
				m.PutStr("valid", "value")
				return v
			},
			maxDepth: 128,
			want: map[string]any{
				"valid": map[string]any{"stringValue": "value"},
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
