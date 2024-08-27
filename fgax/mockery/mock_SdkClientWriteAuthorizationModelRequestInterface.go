// Code generated by mockery. DO NOT EDIT.

package client

import (
	context "context"

	client "github.com/openfga/go-sdk/client"

	mock "github.com/stretchr/testify/mock"

	openfga "github.com/openfga/go-sdk"
)

// MockSdkClientWriteAuthorizationModelRequestInterface is an autogenerated mock type for the SdkClientWriteAuthorizationModelRequestInterface type
type MockSdkClientWriteAuthorizationModelRequestInterface struct {
	mock.Mock
}

type MockSdkClientWriteAuthorizationModelRequestInterface_Expecter struct {
	mock *mock.Mock
}

func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) EXPECT() *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_Expecter{mock: &_m.Mock}
}

// Body provides a mock function with given fields: body
func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) Body(body openfga.WriteAuthorizationModelRequest) client.SdkClientWriteAuthorizationModelRequestInterface {
	ret := _m.Called(body)

	if len(ret) == 0 {
		panic("no return value specified for Body")
	}

	var r0 client.SdkClientWriteAuthorizationModelRequestInterface
	if rf, ok := ret.Get(0).(func(openfga.WriteAuthorizationModelRequest) client.SdkClientWriteAuthorizationModelRequestInterface); ok {
		r0 = rf(body)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientWriteAuthorizationModelRequestInterface)
		}
	}

	return r0
}

// MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Body'
type MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call struct {
	*mock.Call
}

// Body is a helper method to define mock.On call
//   - body openfga.WriteAuthorizationModelRequest
func (_e *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter) Body(body interface{}) *MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call{Call: _e.mock.On("Body", body)}
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call) Run(run func(body openfga.WriteAuthorizationModelRequest)) *MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(openfga.WriteAuthorizationModelRequest))
	})
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call) Return(_a0 client.SdkClientWriteAuthorizationModelRequestInterface) *MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call) RunAndReturn(run func(openfga.WriteAuthorizationModelRequest) client.SdkClientWriteAuthorizationModelRequestInterface) *MockSdkClientWriteAuthorizationModelRequestInterface_Body_Call {
	_c.Call.Return(run)
	return _c
}

// Execute provides a mock function with given fields:
func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) Execute() (*openfga.WriteAuthorizationModelResponse, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 *openfga.WriteAuthorizationModelResponse
	var r1 error
	if rf, ok := ret.Get(0).(func() (*openfga.WriteAuthorizationModelResponse, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *openfga.WriteAuthorizationModelResponse); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*openfga.WriteAuthorizationModelResponse)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
func (_e *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter) Execute() *MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call{Call: _e.mock.On("Execute")}
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call) Run(run func()) *MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call) Return(_a0 *openfga.WriteAuthorizationModelResponse, _a1 error) *MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call) RunAndReturn(run func() (*openfga.WriteAuthorizationModelResponse, error)) *MockSdkClientWriteAuthorizationModelRequestInterface_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// GetBody provides a mock function with given fields:
func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) GetBody() *openfga.WriteAuthorizationModelRequest {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetBody")
	}

	var r0 *openfga.WriteAuthorizationModelRequest
	if rf, ok := ret.Get(0).(func() *openfga.WriteAuthorizationModelRequest); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*openfga.WriteAuthorizationModelRequest)
		}
	}

	return r0
}

// MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetBody'
type MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call struct {
	*mock.Call
}

// GetBody is a helper method to define mock.On call
func (_e *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter) GetBody() *MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call{Call: _e.mock.On("GetBody")}
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call) Run(run func()) *MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call) Return(_a0 *openfga.WriteAuthorizationModelRequest) *MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call) RunAndReturn(run func() *openfga.WriteAuthorizationModelRequest) *MockSdkClientWriteAuthorizationModelRequestInterface_GetBody_Call {
	_c.Call.Return(run)
	return _c
}

// GetContext provides a mock function with given fields:
func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) GetContext() context.Context {
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

// MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetContext'
type MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call struct {
	*mock.Call
}

// GetContext is a helper method to define mock.On call
func (_e *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter) GetContext() *MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call{Call: _e.mock.On("GetContext")}
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call) Run(run func()) *MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call) Return(_a0 context.Context) *MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call) RunAndReturn(run func() context.Context) *MockSdkClientWriteAuthorizationModelRequestInterface_GetContext_Call {
	_c.Call.Return(run)
	return _c
}

// GetOptions provides a mock function with given fields:
func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) GetOptions() *client.ClientWriteAuthorizationModelOptions {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetOptions")
	}

	var r0 *client.ClientWriteAuthorizationModelOptions
	if rf, ok := ret.Get(0).(func() *client.ClientWriteAuthorizationModelOptions); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ClientWriteAuthorizationModelOptions)
		}
	}

	return r0
}

// MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOptions'
type MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call struct {
	*mock.Call
}

// GetOptions is a helper method to define mock.On call
func (_e *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter) GetOptions() *MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call{Call: _e.mock.On("GetOptions")}
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call) Run(run func()) *MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call) Return(_a0 *client.ClientWriteAuthorizationModelOptions) *MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call) RunAndReturn(run func() *client.ClientWriteAuthorizationModelOptions) *MockSdkClientWriteAuthorizationModelRequestInterface_GetOptions_Call {
	_c.Call.Return(run)
	return _c
}

// GetStoreIdOverride provides a mock function with given fields:
func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) GetStoreIdOverride() *string {
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

// MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetStoreIdOverride'
type MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call struct {
	*mock.Call
}

// GetStoreIdOverride is a helper method to define mock.On call
func (_e *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter) GetStoreIdOverride() *MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call{Call: _e.mock.On("GetStoreIdOverride")}
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call) Run(run func()) *MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call) Return(_a0 *string) *MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call) RunAndReturn(run func() *string) *MockSdkClientWriteAuthorizationModelRequestInterface_GetStoreIdOverride_Call {
	_c.Call.Return(run)
	return _c
}

// Options provides a mock function with given fields: options
func (_m *MockSdkClientWriteAuthorizationModelRequestInterface) Options(options client.ClientWriteAuthorizationModelOptions) client.SdkClientWriteAuthorizationModelRequestInterface {
	ret := _m.Called(options)

	if len(ret) == 0 {
		panic("no return value specified for Options")
	}

	var r0 client.SdkClientWriteAuthorizationModelRequestInterface
	if rf, ok := ret.Get(0).(func(client.ClientWriteAuthorizationModelOptions) client.SdkClientWriteAuthorizationModelRequestInterface); ok {
		r0 = rf(options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(client.SdkClientWriteAuthorizationModelRequestInterface)
		}
	}

	return r0
}

// MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Options'
type MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call struct {
	*mock.Call
}

// Options is a helper method to define mock.On call
//   - options client.ClientWriteAuthorizationModelOptions
func (_e *MockSdkClientWriteAuthorizationModelRequestInterface_Expecter) Options(options interface{}) *MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call {
	return &MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call{Call: _e.mock.On("Options", options)}
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call) Run(run func(options client.ClientWriteAuthorizationModelOptions)) *MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.ClientWriteAuthorizationModelOptions))
	})
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call) Return(_a0 client.SdkClientWriteAuthorizationModelRequestInterface) *MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call) RunAndReturn(run func(client.ClientWriteAuthorizationModelOptions) client.SdkClientWriteAuthorizationModelRequestInterface) *MockSdkClientWriteAuthorizationModelRequestInterface_Options_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockSdkClientWriteAuthorizationModelRequestInterface creates a new instance of MockSdkClientWriteAuthorizationModelRequestInterface. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockSdkClientWriteAuthorizationModelRequestInterface(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockSdkClientWriteAuthorizationModelRequestInterface {
	mock := &MockSdkClientWriteAuthorizationModelRequestInterface{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}