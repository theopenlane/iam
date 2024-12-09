// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"

	client "github.com/openfga/go-sdk/client"

	mock "github.com/stretchr/testify/mock"
)

// MockSdkClientReadAuthorizationModelRequestInterface is an autogenerated mock type for the SdkClientReadAuthorizationModelRequestInterface type
type MockSdkClientReadAuthorizationModelRequestInterface struct {
	mock.Mock
}

type MockSdkClientReadAuthorizationModelRequestInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSdkClientReadAuthorizationModelRequestInterface) EXPECT() *MockSdkClientReadAuthorizationModelRequestInterface_Expecter {
	return &MockSdkClientReadAuthorizationModelRequestInterface_Expecter{mock: &_m.Mock}
}

// Body provides a mock function with given fields: body
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) Body(body client.ClientReadAuthorizationModelRequest) client.SdkClientReadAuthorizationModelRequestInterface {
	ret := _m.Called(body)

	if len(ret) == 0 {
		panic("no return value specified for Body")
	}

	var r0 client.SdkClientReadAuthorizationModelRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientReadAuthorizationModelRequest) client.SdkClientReadAuthorizationModelRequestInterface); ok {
		r0 = rf(body)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientReadAuthorizationModelRequestInterface)
		}
	}

	return r0
}

// MockSdkClientReadAuthorizationModelRequestInterface_Body_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Body'
type MockSdkClientReadAuthorizationModelRequestInterface_Body_Call struct {
	*mock.Call
}

// Body is a helper method to define mock.On call
//   - body client.ClientReadAuthorizationModelRequest
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) Body(body interface{}) *MockSdkClientReadAuthorizationModelRequestInterface_Body_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_Body_Call{Call: _e.mock.On("Body", body)}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Body_Call) Run(run func(body client.ClientReadAuthorizationModelRequest)) *MockSdkClientReadAuthorizationModelRequestInterface_Body_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientReadAuthorizationModelRequest))
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Body_Call) Return(_a0 client.SdkClientReadAuthorizationModelRequestInterface) *MockSdkClientReadAuthorizationModelRequestInterface_Body_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Body_Call) RunAndReturn(run func(client.ClientReadAuthorizationModelRequest) client.SdkClientReadAuthorizationModelRequestInterface) *MockSdkClientReadAuthorizationModelRequestInterface_Body_Call {
	_c.Call.Return(run)
	return _c
}

// Execute provides a mock function with no fields
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) Execute() (*client.ClientReadAuthorizationModelResponse, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 *client.ClientReadAuthorizationModelResponse
	var r1 error
	if rf, ok := ret.Get(0).(func() (*client.ClientReadAuthorizationModelResponse, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *client.ClientReadAuthorizationModelResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientReadAuthorizationModelResponse)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) Execute() *MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call{Call: _e.mock.On("Execute")}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call) Run(run func()) *MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call) Return(_a0 *client.ClientReadAuthorizationModelResponse, _a1 error) *MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call) RunAndReturn(run func() (*client.ClientReadAuthorizationModelResponse, error)) *MockSdkClientReadAuthorizationModelRequestInterface_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// GetAuthorizationModelIdOverride provides a mock function with no fields
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) GetAuthorizationModelIdOverride() *string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetAuthorizationModelIdOverride")
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

// MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAuthorizationModelIdOverride'
type MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call struct {
	*mock.Call
}

// GetAuthorizationModelIdOverride is a helper method to define mock.On call
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) GetAuthorizationModelIdOverride() *MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call{Call: _e.mock.On("GetAuthorizationModelIdOverride")}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call) Run(run func()) *MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call) Return(_a0 *string) *MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call) RunAndReturn(run func() *string) *MockSdkClientReadAuthorizationModelRequestInterface_GetAuthorizationModelIdOverride_Call {
	_c.Call.Return(run)
	return _c
}

// GetBody provides a mock function with no fields
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) GetBody() *client.ClientReadAuthorizationModelRequest {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetBody")
	}

	var r0 *client.ClientReadAuthorizationModelRequest
	if rf, ok := ret.Get(0).(func() *client.ClientReadAuthorizationModelRequest); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientReadAuthorizationModelRequest)
		}
	}

	return r0
}

// MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBody'
type MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call struct {
	*mock.Call
}

// GetBody is a helper method to define mock.On call
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) GetBody() *MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call{Call: _e.mock.On("GetBody")}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call) Run(run func()) *MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call) Return(_a0 *client.ClientReadAuthorizationModelRequest) *MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call) RunAndReturn(run func() *client.ClientReadAuthorizationModelRequest) *MockSdkClientReadAuthorizationModelRequestInterface_GetBody_Call {
	_c.Call.Return(run)
	return _c
}

// GetContext provides a mock function with no fields
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) GetContext() context.Context {
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

// MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetContext'
type MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call struct {
	*mock.Call
}

// GetContext is a helper method to define mock.On call
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) GetContext() *MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call{Call: _e.mock.On("GetContext")}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call) Run(run func()) *MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call) Return(_a0 context.Context) *MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call) RunAndReturn(run func() context.Context) *MockSdkClientReadAuthorizationModelRequestInterface_GetContext_Call {
	_c.Call.Return(run)
	return _c
}

// GetOptions provides a mock function with no fields
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) GetOptions() *client.ClientReadAuthorizationModelOptions {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetOptions")
	}

	var r0 *client.ClientReadAuthorizationModelOptions
	if rf, ok := ret.Get(0).(func() *client.ClientReadAuthorizationModelOptions); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientReadAuthorizationModelOptions)
		}
	}

	return r0
}

// MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOptions'
type MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call struct {
	*mock.Call
}

// GetOptions is a helper method to define mock.On call
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) GetOptions() *MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call{Call: _e.mock.On("GetOptions")}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call) Run(run func()) *MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call) Return(_a0 *client.ClientReadAuthorizationModelOptions) *MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call) RunAndReturn(run func() *client.ClientReadAuthorizationModelOptions) *MockSdkClientReadAuthorizationModelRequestInterface_GetOptions_Call {
	_c.Call.Return(run)
	return _c
}

// GetStoreIdOverride provides a mock function with no fields
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) GetStoreIdOverride() *string {
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

// MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetStoreIdOverride'
type MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call struct {
	*mock.Call
}

// GetStoreIdOverride is a helper method to define mock.On call
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) GetStoreIdOverride() *MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call{Call: _e.mock.On("GetStoreIdOverride")}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call) Run(run func()) *MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call) Return(_a0 *string) *MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call) RunAndReturn(run func() *string) *MockSdkClientReadAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(run)
	return _c
}

// Options provides a mock function with given fields: options
func (_m *MockSdkClientReadAuthorizationModelRequestInterface) Options(options client.ClientReadAuthorizationModelOptions) client.SdkClientReadAuthorizationModelRequestInterface {
	ret := _m.Called(options)

	if len(ret) == 0 {
		panic("no return value specified for Options")
	}

	var r0 client.SdkClientReadAuthorizationModelRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientReadAuthorizationModelOptions) client.SdkClientReadAuthorizationModelRequestInterface); ok {
		r0 = rf(options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientReadAuthorizationModelRequestInterface)
		}
	}

	return r0
}

// MockSdkClientReadAuthorizationModelRequestInterface_Options_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Options'
type MockSdkClientReadAuthorizationModelRequestInterface_Options_Call struct {
	*mock.Call
}

// Options is a helper method to define mock.On call
//   - options client.ClientReadAuthorizationModelOptions
func (_e *MockSdkClientReadAuthorizationModelRequestInterface_Expecter) Options(options interface{}) *MockSdkClientReadAuthorizationModelRequestInterface_Options_Call {
	return &MockSdkClientReadAuthorizationModelRequestInterface_Options_Call{Call: _e.mock.On("Options", options)}
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Options_Call) Run(run func(options client.ClientReadAuthorizationModelOptions)) *MockSdkClientReadAuthorizationModelRequestInterface_Options_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientReadAuthorizationModelOptions))
	})
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Options_Call) Return(_a0 client.SdkClientReadAuthorizationModelRequestInterface) *MockSdkClientReadAuthorizationModelRequestInterface_Options_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientReadAuthorizationModelRequestInterface_Options_Call) RunAndReturn(run func(client.ClientReadAuthorizationModelOptions) client.SdkClientReadAuthorizationModelRequestInterface) *MockSdkClientReadAuthorizationModelRequestInterface_Options_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSdkClientReadAuthorizationModelRequestInterface creates a new instance of MockSdkClientReadAuthorizationModelRequestInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSdkClientReadAuthorizationModelRequestInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSdkClientReadAuthorizationModelRequestInterface {
	mock := &MockSdkClientReadAuthorizationModelRequestInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
