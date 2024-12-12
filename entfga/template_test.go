package entfga

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasMutationInputSet(t *testing.T) {
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

func TestExtractDefaultObjectType(t *testing.T) {
	testCases := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "valid schema name",
			input:    "UserHistory",
			expected: "user",
		},
		{
			name:     "valid schema name",
			input:    "ControlObjective",
			expected: "control_objective",
		},
		{
			name:     "valid schema name, lowercase",
			input:    "userhistory",
			expected: "user",
		},
		{
			name:     "schema name without history",
			input:    "User",
			expected: "user",
		},
		{
			name:     "nil input",
			input:    nil,
			expected: "",
		},
		{
			name:     "invalid input type",
			input:    123,
			expected: "",
		},
		{
			name:     "empty string input",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := extractDefaultObjectType(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
