// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"

	client "github.com/openfga/go-sdk/client"

	mock "github.com/stretchr/testify/mock"
)

// MockSdkClientBatchCheckRequestInterface is an autogenerated mock type for the SdkClientBatchCheckRequestInterface type
type MockSdkClientBatchCheckRequestInterface struct {
	mock.Mock
}

type MockSdkClientBatchCheckRequestInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSdkClientBatchCheckRequestInterface) EXPECT() *MockSdkClientBatchCheckRequestInterface_Expecter {
	return &MockSdkClientBatchCheckRequestInterface_Expecter{mock: &_m.Mock}
}

// Body provides a mock function with given fields: body
func (_m *MockSdkClientBatchCheckRequestInterface) Body(body client.ClientBatchCheckBody) client.SdkClientBatchCheckRequestInterface {
	ret := _m.Called(body)

	if len(ret) == 0 {
		panic("no return value specified for Body")
	}

	var r0 client.SdkClientBatchCheckRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientBatchCheckBody) client.SdkClientBatchCheckRequestInterface); ok {
		r0 = rf(body)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientBatchCheckRequestInterface)
		}
	}

	return r0
}

// MockSdkClientBatchCheckRequestInterface_Body_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Body'
type MockSdkClientBatchCheckRequestInterface_Body_Call struct {
	*mock.Call
}

// Body is a helper method to define mock.On call
//   - body client.ClientBatchCheckBody
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) Body(body interface{}) *MockSdkClientBatchCheckRequestInterface_Body_Call {
	return &MockSdkClientBatchCheckRequestInterface_Body_Call{Call: _e.mock.On("Body", body)}
}

func (_c *MockSdkClientBatchCheckRequestInterface_Body_Call) Run(run func(body client.ClientBatchCheckBody)) *MockSdkClientBatchCheckRequestInterface_Body_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientBatchCheckBody))
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_Body_Call) Return(_a0 client.SdkClientBatchCheckRequestInterface) *MockSdkClientBatchCheckRequestInterface_Body_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_Body_Call) RunAndReturn(run func(client.ClientBatchCheckBody) client.SdkClientBatchCheckRequestInterface) *MockSdkClientBatchCheckRequestInterface_Body_Call {
	_c.Call.Return(run)
	return _c
}

// Execute provides a mock function with no fields
func (_m *MockSdkClientBatchCheckRequestInterface) Execute() (*client.ClientBatchCheckResponse, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 *client.ClientBatchCheckResponse
	var r1 error
	if rf, ok := ret.Get(0).(func() (*client.ClientBatchCheckResponse, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *client.ClientBatchCheckResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientBatchCheckResponse)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSdkClientBatchCheckRequestInterface_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockSdkClientBatchCheckRequestInterface_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) Execute() *MockSdkClientBatchCheckRequestInterface_Execute_Call {
	return &MockSdkClientBatchCheckRequestInterface_Execute_Call{Call: _e.mock.On("Execute")}
}

func (_c *MockSdkClientBatchCheckRequestInterface_Execute_Call) Run(run func()) *MockSdkClientBatchCheckRequestInterface_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_Execute_Call) Return(_a0 *client.ClientBatchCheckResponse, _a1 error) *MockSdkClientBatchCheckRequestInterface_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_Execute_Call) RunAndReturn(run func() (*client.ClientBatchCheckResponse, error)) *MockSdkClientBatchCheckRequestInterface_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// GetAuthorizationModelIdOverride provides a mock function with no fields
func (_m *MockSdkClientBatchCheckRequestInterface) GetAuthorizationModelIdOverride() *string {
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

// MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAuthorizationModelIdOverride'
type MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call struct {
	*mock.Call
}

// GetAuthorizationModelIdOverride is a helper method to define mock.On call
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) GetAuthorizationModelIdOverride() *MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call {
	return &MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call{Call: _e.mock.On("GetAuthorizationModelIdOverride")}
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call) Run(run func()) *MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call) Return(_a0 *string) *MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call) RunAndReturn(run func() *string) *MockSdkClientBatchCheckRequestInterface_GetAuthorizationModelIdOverride_Call {
	_c.Call.Return(run)
	return _c
}

// GetBody provides a mock function with no fields
func (_m *MockSdkClientBatchCheckRequestInterface) GetBody() *client.ClientBatchCheckBody {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetBody")
	}

	var r0 *client.ClientBatchCheckBody
	if rf, ok := ret.Get(0).(func() *client.ClientBatchCheckBody); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientBatchCheckBody)
		}
	}

	return r0
}

// MockSdkClientBatchCheckRequestInterface_GetBody_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBody'
type MockSdkClientBatchCheckRequestInterface_GetBody_Call struct {
	*mock.Call
}

// GetBody is a helper method to define mock.On call
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) GetBody() *MockSdkClientBatchCheckRequestInterface_GetBody_Call {
	return &MockSdkClientBatchCheckRequestInterface_GetBody_Call{Call: _e.mock.On("GetBody")}
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetBody_Call) Run(run func()) *MockSdkClientBatchCheckRequestInterface_GetBody_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetBody_Call) Return(_a0 *client.ClientBatchCheckBody) *MockSdkClientBatchCheckRequestInterface_GetBody_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetBody_Call) RunAndReturn(run func() *client.ClientBatchCheckBody) *MockSdkClientBatchCheckRequestInterface_GetBody_Call {
	_c.Call.Return(run)
	return _c
}

// GetContext provides a mock function with no fields
func (_m *MockSdkClientBatchCheckRequestInterface) GetContext() context.Context {
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

// MockSdkClientBatchCheckRequestInterface_GetContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetContext'
type MockSdkClientBatchCheckRequestInterface_GetContext_Call struct {
	*mock.Call
}

// GetContext is a helper method to define mock.On call
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) GetContext() *MockSdkClientBatchCheckRequestInterface_GetContext_Call {
	return &MockSdkClientBatchCheckRequestInterface_GetContext_Call{Call: _e.mock.On("GetContext")}
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetContext_Call) Run(run func()) *MockSdkClientBatchCheckRequestInterface_GetContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetContext_Call) Return(_a0 context.Context) *MockSdkClientBatchCheckRequestInterface_GetContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetContext_Call) RunAndReturn(run func() context.Context) *MockSdkClientBatchCheckRequestInterface_GetContext_Call {
	_c.Call.Return(run)
	return _c
}

// GetOptions provides a mock function with no fields
func (_m *MockSdkClientBatchCheckRequestInterface) GetOptions() *client.ClientBatchCheckOptions {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetOptions")
	}

	var r0 *client.ClientBatchCheckOptions
	if rf, ok := ret.Get(0).(func() *client.ClientBatchCheckOptions); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientBatchCheckOptions)
		}
	}

	return r0
}

// MockSdkClientBatchCheckRequestInterface_GetOptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOptions'
type MockSdkClientBatchCheckRequestInterface_GetOptions_Call struct {
	*mock.Call
}

// GetOptions is a helper method to define mock.On call
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) GetOptions() *MockSdkClientBatchCheckRequestInterface_GetOptions_Call {
	return &MockSdkClientBatchCheckRequestInterface_GetOptions_Call{Call: _e.mock.On("GetOptions")}
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetOptions_Call) Run(run func()) *MockSdkClientBatchCheckRequestInterface_GetOptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetOptions_Call) Return(_a0 *client.ClientBatchCheckOptions) *MockSdkClientBatchCheckRequestInterface_GetOptions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetOptions_Call) RunAndReturn(run func() *client.ClientBatchCheckOptions) *MockSdkClientBatchCheckRequestInterface_GetOptions_Call {
	_c.Call.Return(run)
	return _c
}

// GetStoreIdOverride provides a mock function with no fields
func (_m *MockSdkClientBatchCheckRequestInterface) GetStoreIdOverride() *string {
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

// MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetStoreIdOverride'
type MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call struct {
	*mock.Call
}

// GetStoreIdOverride is a helper method to define mock.On call
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) GetStoreIdOverride() *MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call {
	return &MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call{Call: _e.mock.On("GetStoreIdOverride")}
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call) Run(run func()) *MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call) Return(_a0 *string) *MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call) RunAndReturn(run func() *string) *MockSdkClientBatchCheckRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(run)
	return _c
}

// Options provides a mock function with given fields: options
func (_m *MockSdkClientBatchCheckRequestInterface) Options(options client.ClientBatchCheckOptions) client.SdkClientBatchCheckRequestInterface {
	ret := _m.Called(options)

	if len(ret) == 0 {
		panic("no return value specified for Options")
	}

	var r0 client.SdkClientBatchCheckRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientBatchCheckOptions) client.SdkClientBatchCheckRequestInterface); ok {
		r0 = rf(options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientBatchCheckRequestInterface)
		}
	}

	return r0
}

// MockSdkClientBatchCheckRequestInterface_Options_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Options'
type MockSdkClientBatchCheckRequestInterface_Options_Call struct {
	*mock.Call
}

// Options is a helper method to define mock.On call
//   - options client.ClientBatchCheckOptions
func (_e *MockSdkClientBatchCheckRequestInterface_Expecter) Options(options interface{}) *MockSdkClientBatchCheckRequestInterface_Options_Call {
	return &MockSdkClientBatchCheckRequestInterface_Options_Call{Call: _e.mock.On("Options", options)}
}

func (_c *MockSdkClientBatchCheckRequestInterface_Options_Call) Run(run func(options client.ClientBatchCheckOptions)) *MockSdkClientBatchCheckRequestInterface_Options_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientBatchCheckOptions))
	})
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_Options_Call) Return(_a0 client.SdkClientBatchCheckRequestInterface) *MockSdkClientBatchCheckRequestInterface_Options_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientBatchCheckRequestInterface_Options_Call) RunAndReturn(run func(client.ClientBatchCheckOptions) client.SdkClientBatchCheckRequestInterface) *MockSdkClientBatchCheckRequestInterface_Options_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSdkClientBatchCheckRequestInterface creates a new instance of MockSdkClientBatchCheckRequestInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSdkClientBatchCheckRequestInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSdkClientBatchCheckRequestInterface {
	mock := &MockSdkClientBatchCheckRequestInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
