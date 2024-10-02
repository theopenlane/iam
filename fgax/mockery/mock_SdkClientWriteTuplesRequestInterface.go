// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"

	client "github.com/openfga/go-sdk/client"

	mock "github.com/stretchr/testify/mock"
)

// MockSdkClientWriteTuplesRequestInterface is an autogenerated mock type for the SdkClientWriteTuplesRequestInterface type
type MockSdkClientWriteTuplesRequestInterface struct {
	mock.Mock
}

type MockSdkClientWriteTuplesRequestInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSdkClientWriteTuplesRequestInterface) EXPECT() *MockSdkClientWriteTuplesRequestInterface_Expecter {
	return &MockSdkClientWriteTuplesRequestInterface_Expecter{mock: &_m.Mock}
}

// Body provides a mock function with given fields: body
func (_m *MockSdkClientWriteTuplesRequestInterface) Body(body client.ClientWriteTuplesBody) client.SdkClientWriteTuplesRequestInterface {
	ret := _m.Called(body)

	if len(ret) == 0 {
		panic("no return value specified for Body")
	}

	var r0 client.SdkClientWriteTuplesRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientWriteTuplesBody) client.SdkClientWriteTuplesRequestInterface); ok {
		r0 = rf(body)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientWriteTuplesRequestInterface)
		}
	}

	return r0
}

// MockSdkClientWriteTuplesRequestInterface_Body_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Body'
type MockSdkClientWriteTuplesRequestInterface_Body_Call struct {
	*mock.Call
}

// Body is a helper method to define mock.On call
//   - body client.ClientWriteTuplesBody
func (_e *MockSdkClientWriteTuplesRequestInterface_Expecter) Body(body interface{}) *MockSdkClientWriteTuplesRequestInterface_Body_Call {
	return &MockSdkClientWriteTuplesRequestInterface_Body_Call{Call: _e.mock.On("Body", body)}
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Body_Call) Run(run func(body client.ClientWriteTuplesBody)) *MockSdkClientWriteTuplesRequestInterface_Body_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientWriteTuplesBody))
	})
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Body_Call) Return(_a0 client.SdkClientWriteTuplesRequestInterface) *MockSdkClientWriteTuplesRequestInterface_Body_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Body_Call) RunAndReturn(run func(client.ClientWriteTuplesBody) client.SdkClientWriteTuplesRequestInterface) *MockSdkClientWriteTuplesRequestInterface_Body_Call {
	_c.Call.Return(run)
	return _c
}

// Execute provides a mock function with given fields:
func (_m *MockSdkClientWriteTuplesRequestInterface) Execute() (*client.ClientWriteResponse, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 *client.ClientWriteResponse
	var r1 error
	if rf, ok := ret.Get(0).(func() (*client.ClientWriteResponse, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *client.ClientWriteResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientWriteResponse)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSdkClientWriteTuplesRequestInterface_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockSdkClientWriteTuplesRequestInterface_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
func (_e *MockSdkClientWriteTuplesRequestInterface_Expecter) Execute() *MockSdkClientWriteTuplesRequestInterface_Execute_Call {
	return &MockSdkClientWriteTuplesRequestInterface_Execute_Call{Call: _e.mock.On("Execute")}
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Execute_Call) Run(run func()) *MockSdkClientWriteTuplesRequestInterface_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Execute_Call) Return(_a0 *client.ClientWriteResponse, _a1 error) *MockSdkClientWriteTuplesRequestInterface_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Execute_Call) RunAndReturn(run func() (*client.ClientWriteResponse, error)) *MockSdkClientWriteTuplesRequestInterface_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// GetBody provides a mock function with given fields:
func (_m *MockSdkClientWriteTuplesRequestInterface) GetBody() *client.ClientWriteTuplesBody {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetBody")
	}

	var r0 *client.ClientWriteTuplesBody
	if rf, ok := ret.Get(0).(func() *client.ClientWriteTuplesBody); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientWriteTuplesBody)
		}
	}

	return r0
}

// MockSdkClientWriteTuplesRequestInterface_GetBody_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBody'
type MockSdkClientWriteTuplesRequestInterface_GetBody_Call struct {
	*mock.Call
}

// GetBody is a helper method to define mock.On call
func (_e *MockSdkClientWriteTuplesRequestInterface_Expecter) GetBody() *MockSdkClientWriteTuplesRequestInterface_GetBody_Call {
	return &MockSdkClientWriteTuplesRequestInterface_GetBody_Call{Call: _e.mock.On("GetBody")}
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetBody_Call) Run(run func()) *MockSdkClientWriteTuplesRequestInterface_GetBody_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetBody_Call) Return(_a0 *client.ClientWriteTuplesBody) *MockSdkClientWriteTuplesRequestInterface_GetBody_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetBody_Call) RunAndReturn(run func() *client.ClientWriteTuplesBody) *MockSdkClientWriteTuplesRequestInterface_GetBody_Call {
	_c.Call.Return(run)
	return _c
}

// GetContext provides a mock function with given fields:
func (_m *MockSdkClientWriteTuplesRequestInterface) GetContext() context.Context {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetContext")
	}

	var r0 context.Context
	if rf, ok := ret.Get(0).(func() context.Context); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(context.Context)
		}
	}

	return r0
}

// MockSdkClientWriteTuplesRequestInterface_GetContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetContext'
type MockSdkClientWriteTuplesRequestInterface_GetContext_Call struct {
	*mock.Call
}

// GetContext is a helper method to define mock.On call
func (_e *MockSdkClientWriteTuplesRequestInterface_Expecter) GetContext() *MockSdkClientWriteTuplesRequestInterface_GetContext_Call {
	return &MockSdkClientWriteTuplesRequestInterface_GetContext_Call{Call: _e.mock.On("GetContext")}
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetContext_Call) Run(run func()) *MockSdkClientWriteTuplesRequestInterface_GetContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetContext_Call) Return(_a0 context.Context) *MockSdkClientWriteTuplesRequestInterface_GetContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetContext_Call) RunAndReturn(run func() context.Context) *MockSdkClientWriteTuplesRequestInterface_GetContext_Call {
	_c.Call.Return(run)
	return _c
}

// GetOptions provides a mock function with given fields:
func (_m *MockSdkClientWriteTuplesRequestInterface) GetOptions() *client.ClientWriteOptions {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetOptions")
	}

	var r0 *client.ClientWriteOptions
	if rf, ok := ret.Get(0).(func() *client.ClientWriteOptions); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientWriteOptions)
		}
	}

	return r0
}

// MockSdkClientWriteTuplesRequestInterface_GetOptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOptions'
type MockSdkClientWriteTuplesRequestInterface_GetOptions_Call struct {
	*mock.Call
}

// GetOptions is a helper method to define mock.On call
func (_e *MockSdkClientWriteTuplesRequestInterface_Expecter) GetOptions() *MockSdkClientWriteTuplesRequestInterface_GetOptions_Call {
	return &MockSdkClientWriteTuplesRequestInterface_GetOptions_Call{Call: _e.mock.On("GetOptions")}
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetOptions_Call) Run(run func()) *MockSdkClientWriteTuplesRequestInterface_GetOptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetOptions_Call) Return(_a0 *client.ClientWriteOptions) *MockSdkClientWriteTuplesRequestInterface_GetOptions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_GetOptions_Call) RunAndReturn(run func() *client.ClientWriteOptions) *MockSdkClientWriteTuplesRequestInterface_GetOptions_Call {
	_c.Call.Return(run)
	return _c
}

// Options provides a mock function with given fields: options
func (_m *MockSdkClientWriteTuplesRequestInterface) Options(options client.ClientWriteOptions) client.SdkClientWriteTuplesRequestInterface {
	ret := _m.Called(options)

	if len(ret) == 0 {
		panic("no return value specified for Options")
	}

	var r0 client.SdkClientWriteTuplesRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientWriteOptions) client.SdkClientWriteTuplesRequestInterface); ok {
		r0 = rf(options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientWriteTuplesRequestInterface)
		}
	}

	return r0
}

// MockSdkClientWriteTuplesRequestInterface_Options_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Options'
type MockSdkClientWriteTuplesRequestInterface_Options_Call struct {
	*mock.Call
}

// Options is a helper method to define mock.On call
//   - options client.ClientWriteOptions
func (_e *MockSdkClientWriteTuplesRequestInterface_Expecter) Options(options interface{}) *MockSdkClientWriteTuplesRequestInterface_Options_Call {
	return &MockSdkClientWriteTuplesRequestInterface_Options_Call{Call: _e.mock.On("Options", options)}
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Options_Call) Run(run func(options client.ClientWriteOptions)) *MockSdkClientWriteTuplesRequestInterface_Options_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientWriteOptions))
	})
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Options_Call) Return(_a0 client.SdkClientWriteTuplesRequestInterface) *MockSdkClientWriteTuplesRequestInterface_Options_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteTuplesRequestInterface_Options_Call) RunAndReturn(run func(client.ClientWriteOptions) client.SdkClientWriteTuplesRequestInterface) *MockSdkClientWriteTuplesRequestInterface_Options_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSdkClientWriteTuplesRequestInterface creates a new instance of MockSdkClientWriteTuplesRequestInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSdkClientWriteTuplesRequestInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSdkClientWriteTuplesRequestInterface {
	mock := &MockSdkClientWriteTuplesRequestInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
