// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"

	client "github.com/openfga/go-sdk/client"

	mock "github.com/stretchr/testify/mock"
)

// MockSdkClientReadRequestInterface is an autogenerated mock type for the SdkClientReadRequestInterface type
type MockSdkClientReadRequestInterface struct {
	mock.Mock
}

type MockSdkClientReadRequestInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSdkClientReadRequestInterface) EXPECT() *MockSdkClientReadRequestInterface_Expecter {
	return &MockSdkClientReadRequestInterface_Expecter{mock: &_m.Mock}
}

// Body provides a mock function with given fields: body
func (_m *MockSdkClientReadRequestInterface) Body(body client.ClientReadRequest) client.SdkClientReadRequestInterface {
	ret := _m.Called(body)

	if len(ret) == 0 {
		panic("no return value specified for Body")
	}

	var r0 client.SdkClientReadRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientReadRequest) client.SdkClientReadRequestInterface); ok {
		r0 = rf(body)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientReadRequestInterface)
		}
	}

	return r0
}

// MockSdkClientReadRequestInterface_Body_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Body'
type MockSdkClientReadRequestInterface_Body_Call struct {
	*mock.Call
}

// Body is a helper method to define mock.On call
//   - body client.ClientReadRequest
func (_e *MockSdkClientReadRequestInterface_Expecter) Body(body interface{}) *MockSdkClientReadRequestInterface_Body_Call {
	return &MockSdkClientReadRequestInterface_Body_Call{Call: _e.mock.On("Body", body)}
}

func (_c *MockSdkClientReadRequestInterface_Body_Call) Run(run func(body client.ClientReadRequest)) *MockSdkClientReadRequestInterface_Body_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientReadRequest))
	})
	return _c
}

func (_c *MockSdkClientReadRequestInterface_Body_Call) Return(_a0 client.SdkClientReadRequestInterface) *MockSdkClientReadRequestInterface_Body_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadRequestInterface_Body_Call) RunAndReturn(run func(client.ClientReadRequest) client.SdkClientReadRequestInterface) *MockSdkClientReadRequestInterface_Body_Call {
	_c.Call.Return(run)
	return _c
}

// Execute provides a mock function with given fields:
func (_m *MockSdkClientReadRequestInterface) Execute() (*client.ClientReadResponse, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 *client.ClientReadResponse
	var r1 error
	if rf, ok := ret.Get(0).(func() (*client.ClientReadResponse, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *client.ClientReadResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientReadResponse)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSdkClientReadRequestInterface_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockSdkClientReadRequestInterface_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
func (_e *MockSdkClientReadRequestInterface_Expecter) Execute() *MockSdkClientReadRequestInterface_Execute_Call {
	return &MockSdkClientReadRequestInterface_Execute_Call{Call: _e.mock.On("Execute")}
}

func (_c *MockSdkClientReadRequestInterface_Execute_Call) Run(run func()) *MockSdkClientReadRequestInterface_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadRequestInterface_Execute_Call) Return(_a0 *client.ClientReadResponse, _a1 error) *MockSdkClientReadRequestInterface_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSdkClientReadRequestInterface_Execute_Call) RunAndReturn(run func() (*client.ClientReadResponse, error)) *MockSdkClientReadRequestInterface_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// GetBody provides a mock function with given fields:
func (_m *MockSdkClientReadRequestInterface) GetBody() *client.ClientReadRequest {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetBody")
	}

	var r0 *client.ClientReadRequest
	if rf, ok := ret.Get(0).(func() *client.ClientReadRequest); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientReadRequest)
		}
	}

	return r0
}

// MockSdkClientReadRequestInterface_GetBody_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBody'
type MockSdkClientReadRequestInterface_GetBody_Call struct {
	*mock.Call
}

// GetBody is a helper method to define mock.On call
func (_e *MockSdkClientReadRequestInterface_Expecter) GetBody() *MockSdkClientReadRequestInterface_GetBody_Call {
	return &MockSdkClientReadRequestInterface_GetBody_Call{Call: _e.mock.On("GetBody")}
}

func (_c *MockSdkClientReadRequestInterface_GetBody_Call) Run(run func()) *MockSdkClientReadRequestInterface_GetBody_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetBody_Call) Return(_a0 *client.ClientReadRequest) *MockSdkClientReadRequestInterface_GetBody_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetBody_Call) RunAndReturn(run func() *client.ClientReadRequest) *MockSdkClientReadRequestInterface_GetBody_Call {
	_c.Call.Return(run)
	return _c
}

// GetContext provides a mock function with given fields:
func (_m *MockSdkClientReadRequestInterface) GetContext() context.Context {
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

// MockSdkClientReadRequestInterface_GetContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetContext'
type MockSdkClientReadRequestInterface_GetContext_Call struct {
	*mock.Call
}

// GetContext is a helper method to define mock.On call
func (_e *MockSdkClientReadRequestInterface_Expecter) GetContext() *MockSdkClientReadRequestInterface_GetContext_Call {
	return &MockSdkClientReadRequestInterface_GetContext_Call{Call: _e.mock.On("GetContext")}
}

func (_c *MockSdkClientReadRequestInterface_GetContext_Call) Run(run func()) *MockSdkClientReadRequestInterface_GetContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetContext_Call) Return(_a0 context.Context) *MockSdkClientReadRequestInterface_GetContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetContext_Call) RunAndReturn(run func() context.Context) *MockSdkClientReadRequestInterface_GetContext_Call {
	_c.Call.Return(run)
	return _c
}

// GetOptions provides a mock function with given fields:
func (_m *MockSdkClientReadRequestInterface) GetOptions() *client.ClientReadOptions {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetOptions")
	}

	var r0 *client.ClientReadOptions
	if rf, ok := ret.Get(0).(func() *client.ClientReadOptions); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientReadOptions)
		}
	}

	return r0
}

// MockSdkClientReadRequestInterface_GetOptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOptions'
type MockSdkClientReadRequestInterface_GetOptions_Call struct {
	*mock.Call
}

// GetOptions is a helper method to define mock.On call
func (_e *MockSdkClientReadRequestInterface_Expecter) GetOptions() *MockSdkClientReadRequestInterface_GetOptions_Call {
	return &MockSdkClientReadRequestInterface_GetOptions_Call{Call: _e.mock.On("GetOptions")}
}

func (_c *MockSdkClientReadRequestInterface_GetOptions_Call) Run(run func()) *MockSdkClientReadRequestInterface_GetOptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetOptions_Call) Return(_a0 *client.ClientReadOptions) *MockSdkClientReadRequestInterface_GetOptions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetOptions_Call) RunAndReturn(run func() *client.ClientReadOptions) *MockSdkClientReadRequestInterface_GetOptions_Call {
	_c.Call.Return(run)
	return _c
}

// GetStoreIdOverride provides a mock function with given fields:
func (_m *MockSdkClientReadRequestInterface) GetStoreIdOverride() *string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetStoreIdOverride")
	}

	var r0 *string
	if rf, ok := ret.Get(0).(func() *string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*string)
		}
	}

	return r0
}

// MockSdkClientReadRequestInterface_GetStoreIdOverride_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetStoreIdOverride'
type MockSdkClientReadRequestInterface_GetStoreIdOverride_Call struct {
	*mock.Call
}

// GetStoreIdOverride is a helper method to define mock.On call
func (_e *MockSdkClientReadRequestInterface_Expecter) GetStoreIdOverride() *MockSdkClientReadRequestInterface_GetStoreIdOverride_Call {
	return &MockSdkClientReadRequestInterface_GetStoreIdOverride_Call{Call: _e.mock.On("GetStoreIdOverride")}
}

func (_c *MockSdkClientReadRequestInterface_GetStoreIdOverride_Call) Run(run func()) *MockSdkClientReadRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetStoreIdOverride_Call) Return(_a0 *string) *MockSdkClientReadRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadRequestInterface_GetStoreIdOverride_Call) RunAndReturn(run func() *string) *MockSdkClientReadRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(run)
	return _c
}

// Options provides a mock function with given fields: options
func (_m *MockSdkClientReadRequestInterface) Options(options client.ClientReadOptions) client.SdkClientReadRequestInterface {
	ret := _m.Called(options)

	if len(ret) == 0 {
		panic("no return value specified for Options")
	}

	var r0 client.SdkClientReadRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientReadOptions) client.SdkClientReadRequestInterface); ok {
		r0 = rf(options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientReadRequestInterface)
		}
	}

	return r0
}

// MockSdkClientReadRequestInterface_Options_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Options'
type MockSdkClientReadRequestInterface_Options_Call struct {
	*mock.Call
}

// Options is a helper method to define mock.On call
//   - options client.ClientReadOptions
func (_e *MockSdkClientReadRequestInterface_Expecter) Options(options interface{}) *MockSdkClientReadRequestInterface_Options_Call {
	return &MockSdkClientReadRequestInterface_Options_Call{Call: _e.mock.On("Options", options)}
}

func (_c *MockSdkClientReadRequestInterface_Options_Call) Run(run func(options client.ClientReadOptions)) *MockSdkClientReadRequestInterface_Options_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientReadOptions))
	})
	return _c
}

func (_c *MockSdkClientReadRequestInterface_Options_Call) Return(_a0 client.SdkClientReadRequestInterface) *MockSdkClientReadRequestInterface_Options_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadRequestInterface_Options_Call) RunAndReturn(run func(client.ClientReadOptions) client.SdkClientReadRequestInterface) *MockSdkClientReadRequestInterface_Options_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSdkClientReadRequestInterface creates a new instance of MockSdkClientReadRequestInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSdkClientReadRequestInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSdkClientReadRequestInterface {
	mock := &MockSdkClientReadRequestInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
