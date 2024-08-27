package entfga

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hasMutationInputSet(t *testing.T) {
	testCases := []struct {
		name     string
		input    any
		expected bool
	}{
		{
			name:     "mutation inputs set",
			input:    map[string]interface{}{"MutationInputs": map[string]interface{}{"IsCreate": true}},
			expected: true,
		},
		{
			name:     "mutation inputs not set",
			input:    map[string]interface{}{},
			expected: false,
		},
		{
			name:     "mutation inputs set to nil",
			input:    map[string]interface{}{"MutationInputs": nil},
			expected: false,
		},
		{
			name:     "invalid input type",
			input:    "invalid",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := hasMutationInputSet(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
