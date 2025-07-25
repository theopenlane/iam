package tokens

import "context"

type MockValidator struct {
	OnVerify            func(string) (*Claims, error)
	OnVerifyWithContext func(context.Context, string) (*Claims, error)
	OnParse             func(string) (*Claims, error)
	Calls               map[string]int
}

var _ Validator = &MockValidator{}

func (m *MockValidator) Verify(tks string) (*Claims, error) {
	m.incr("Verify")

	return m.OnVerify(tks)
}

func (m *MockValidator) VerifyWithContext(ctx context.Context, tks string) (*Claims, error) {
	m.incr("VerifyWithContext")

	if m.OnVerifyWithContext != nil {
		return m.OnVerifyWithContext(ctx, tks)
	}

	// Fallback to regular Verify if VerifyWithContext not set
	return m.OnVerify(tks)
}

func (m *MockValidator) Parse(tks string) (*Claims, error) {
	m.incr("Parse")

	return m.OnParse(tks)
}

func (m *MockValidator) incr(method string) {
	if m.Calls == nil {
		m.Calls = make(map[string]int)
	}

	m.Calls[method]++
}
