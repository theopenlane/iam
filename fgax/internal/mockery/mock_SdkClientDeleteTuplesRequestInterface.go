// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"

	client "github.com/openfga/go-sdk/client"

	mock "github.com/stretchr/testify/mock"
)

// MockSdkClientDeleteTuplesRequestInterface is an autogenerated mock type for the SdkClientDeleteTuplesRequestInterface type
type MockSdkClientDeleteTuplesRequestInterface struct {
	mock.Mock
}

type MockSdkClientDeleteTuplesRequestInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSdkClientDeleteTuplesRequestInterface) EXPECT() *MockSdkClientDeleteTuplesRequestInterface_Expecter {
	return &MockSdkClientDeleteTuplesRequestInterface_Expecter{mock: &_m.Mock}
}

// Body provides a mock function with given fields: body
func (_m *MockSdkClientDeleteTuplesRequestInterface) Body(body client.ClientDeleteTuplesBody) client.SdkClientDeleteTuplesRequestInterface {
	ret := _m.Called(body)

	if len(ret) == 0 {
		panic("no return value specified for Body")
	}

	var r0 client.SdkClientDeleteTuplesRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientDeleteTuplesBody) client.SdkClientDeleteTuplesRequestInterface); ok {
		r0 = rf(body)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientDeleteTuplesRequestInterface)
		}
	}

	return r0
}

// MockSdkClientDeleteTuplesRequestInterface_Body_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Body'
type MockSdkClientDeleteTuplesRequestInterface_Body_Call struct {
	*mock.Call
}

// Body is a helper method to define mock.On call
//   - body client.ClientDeleteTuplesBody
func (_e *MockSdkClientDeleteTuplesRequestInterface_Expecter) Body(body interface{}) *MockSdkClientDeleteTuplesRequestInterface_Body_Call {
	return &MockSdkClientDeleteTuplesRequestInterface_Body_Call{Call: _e.mock.On("Body", body)}
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Body_Call) Run(run func(body client.ClientDeleteTuplesBody)) *MockSdkClientDeleteTuplesRequestInterface_Body_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientDeleteTuplesBody))
	})
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Body_Call) Return(_a0 client.SdkClientDeleteTuplesRequestInterface) *MockSdkClientDeleteTuplesRequestInterface_Body_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Body_Call) RunAndReturn(run func(client.ClientDeleteTuplesBody) client.SdkClientDeleteTuplesRequestInterface) *MockSdkClientDeleteTuplesRequestInterface_Body_Call {
	_c.Call.Return(run)
	return _c
}

// Execute provides a mock function with no fields
func (_m *MockSdkClientDeleteTuplesRequestInterface) Execute() (*client.ClientWriteResponse, error) {
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

// MockSdkClientDeleteTuplesRequestInterface_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockSdkClientDeleteTuplesRequestInterface_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
func (_e *MockSdkClientDeleteTuplesRequestInterface_Expecter) Execute() *MockSdkClientDeleteTuplesRequestInterface_Execute_Call {
	return &MockSdkClientDeleteTuplesRequestInterface_Execute_Call{Call: _e.mock.On("Execute")}
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Execute_Call) Run(run func()) *MockSdkClientDeleteTuplesRequestInterface_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Execute_Call) Return(_a0 *client.ClientWriteResponse, _a1 error) *MockSdkClientDeleteTuplesRequestInterface_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Execute_Call) RunAndReturn(run func() (*client.ClientWriteResponse, error)) *MockSdkClientDeleteTuplesRequestInterface_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// GetBody provides a mock function with no fields
func (_m *MockSdkClientDeleteTuplesRequestInterface) GetBody() *client.ClientDeleteTuplesBody {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetBody")
	}

	var r0 *client.ClientDeleteTuplesBody
	if rf, ok := ret.Get(0).(func() *client.ClientDeleteTuplesBody); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientDeleteTuplesBody)
		}
	}

	return r0
}

// MockSdkClientDeleteTuplesRequestInterface_GetBody_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBody'
type MockSdkClientDeleteTuplesRequestInterface_GetBody_Call struct {
	*mock.Call
}

// GetBody is a helper method to define mock.On call
func (_e *MockSdkClientDeleteTuplesRequestInterface_Expecter) GetBody() *MockSdkClientDeleteTuplesRequestInterface_GetBody_Call {
	return &MockSdkClientDeleteTuplesRequestInterface_GetBody_Call{Call: _e.mock.On("GetBody")}
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetBody_Call) Run(run func()) *MockSdkClientDeleteTuplesRequestInterface_GetBody_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetBody_Call) Return(_a0 *client.ClientDeleteTuplesBody) *MockSdkClientDeleteTuplesRequestInterface_GetBody_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetBody_Call) RunAndReturn(run func() *client.ClientDeleteTuplesBody) *MockSdkClientDeleteTuplesRequestInterface_GetBody_Call {
	_c.Call.Return(run)
	return _c
}

// GetContext provides a mock function with no fields
func (_m *MockSdkClientDeleteTuplesRequestInterface) GetContext() context.Context {
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

// MockSdkClientDeleteTuplesRequestInterface_GetContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetContext'
type MockSdkClientDeleteTuplesRequestInterface_GetContext_Call struct {
	*mock.Call
}

// GetContext is a helper method to define mock.On call
func (_e *MockSdkClientDeleteTuplesRequestInterface_Expecter) GetContext() *MockSdkClientDeleteTuplesRequestInterface_GetContext_Call {
	return &MockSdkClientDeleteTuplesRequestInterface_GetContext_Call{Call: _e.mock.On("GetContext")}
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetContext_Call) Run(run func()) *MockSdkClientDeleteTuplesRequestInterface_GetContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetContext_Call) Return(_a0 context.Context) *MockSdkClientDeleteTuplesRequestInterface_GetContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetContext_Call) RunAndReturn(run func() context.Context) *MockSdkClientDeleteTuplesRequestInterface_GetContext_Call {
	_c.Call.Return(run)
	return _c
}

// GetOptions provides a mock function with no fields
func (_m *MockSdkClientDeleteTuplesRequestInterface) GetOptions() *client.ClientWriteOptions {
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

// MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOptions'
type MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call struct {
	*mock.Call
}

// GetOptions is a helper method to define mock.On call
func (_e *MockSdkClientDeleteTuplesRequestInterface_Expecter) GetOptions() *MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call {
	return &MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call{Call: _e.mock.On("GetOptions")}
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call) Run(run func()) *MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call) Return(_a0 *client.ClientWriteOptions) *MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call) RunAndReturn(run func() *client.ClientWriteOptions) *MockSdkClientDeleteTuplesRequestInterface_GetOptions_Call {
	_c.Call.Return(run)
	return _c
}

// Options provides a mock function with given fields: options
func (_m *MockSdkClientDeleteTuplesRequestInterface) Options(options client.ClientWriteOptions) client.SdkClientDeleteTuplesRequestInterface {
	ret := _m.Called(options)

	if len(ret) == 0 {
		panic("no return value specified for Options")
	}

	var r0 client.SdkClientDeleteTuplesRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientWriteOptions) client.SdkClientDeleteTuplesRequestInterface); ok {
		r0 = rf(options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientDeleteTuplesRequestInterface)
		}
	}

	return r0
}

// MockSdkClientDeleteTuplesRequestInterface_Options_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Options'
type MockSdkClientDeleteTuplesRequestInterface_Options_Call struct {
	*mock.Call
}

// Options is a helper method to define mock.On call
//   - options client.ClientWriteOptions
func (_e *MockSdkClientDeleteTuplesRequestInterface_Expecter) Options(options interface{}) *MockSdkClientDeleteTuplesRequestInterface_Options_Call {
	return &MockSdkClientDeleteTuplesRequestInterface_Options_Call{Call: _e.mock.On("Options", options)}
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Options_Call) Run(run func(options client.ClientWriteOptions)) *MockSdkClientDeleteTuplesRequestInterface_Options_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientWriteOptions))
	})
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Options_Call) Return(_a0 client.SdkClientDeleteTuplesRequestInterface) *MockSdkClientDeleteTuplesRequestInterface_Options_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientDeleteTuplesRequestInterface_Options_Call) RunAndReturn(run func(client.ClientWriteOptions) client.SdkClientDeleteTuplesRequestInterface) *MockSdkClientDeleteTuplesRequestInterface_Options_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSdkClientDeleteTuplesRequestInterface creates a new instance of MockSdkClientDeleteTuplesRequestInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSdkClientDeleteTuplesRequestInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSdkClientDeleteTuplesRequestInterface {
	mock := &MockSdkClientDeleteTuplesRequestInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
