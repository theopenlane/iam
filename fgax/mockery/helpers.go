package client

import (
	"errors"
	"slices"
	"testing"

	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
	mock "github.com/stretchr/testify/mock"
)

// ClearMocks is used to clear mocks in a test loop
// easiest to use `def mock_fga.ClearMocks(c)` so no matter how the test exits
// mocks are always cleared before the next test case
func ClearMocks(c *MockSdkClient) {
	c.ExpectedCalls = c.ExpectedCalls[:0]
}

// WriteAny creates mock write responses based on the mock FGA client for
// any times in a test
func WriteAny(t *testing.T, c *MockSdkClient) {
	wi := NewMockSdkClientWriteRequestInterface(t)

	expectedResponse := ofgaclient.ClientWriteResponse{
		Writes: []ofgaclient.ClientWriteRequestWriteResponse{
			{
				Status: ofgaclient.SUCCESS,
			},
		},
		Deletes: []ofgaclient.ClientWriteRequestDeleteResponse{
			{
				Status: ofgaclient.SUCCESS,
			},
		},
	}

	wi.EXPECT().Execute().Return(&expectedResponse, nil)

	wi.EXPECT().Options(mock.Anything).Return(wi)

	wi.EXPECT().Body(mock.Anything).Return(wi)

	c.EXPECT().Write(mock.Anything).Return(wi)
}

// WriteOnce creates mock write responses based on the mock FGA client
// one time per test
func WriteOnce(t *testing.T, c *MockSdkClient) {
	wi := NewMockSdkClientWriteRequestInterface(t)

	expectedResponse := ofgaclient.ClientWriteResponse{
		Writes: []ofgaclient.ClientWriteRequestWriteResponse{
			{
				Status: ofgaclient.SUCCESS,
			},
		},
		Deletes: []ofgaclient.ClientWriteRequestDeleteResponse{
			{
				Status: ofgaclient.SUCCESS,
			},
		},
	}

	wi.EXPECT().Execute().Return(&expectedResponse, nil)

	wi.EXPECT().Options(mock.Anything).Return(wi)

	wi.EXPECT().Body(mock.Anything).Return(wi)

	c.EXPECT().Write(mock.Anything).Return(wi).Once()
}

// WriteError creates mock write error response based on the mock FGA client for
// any times in a test
func WriteError(t *testing.T, c *MockSdkClient, err error) {
	wi := NewMockSdkClientWriteRequestInterface(t)

	expectedResponse := ofgaclient.ClientWriteResponse{
		Writes: []ofgaclient.ClientWriteRequestWriteResponse{
			{
				Status: ofgaclient.FAILURE,
				Error:  err,
			},
		},
		Deletes: []ofgaclient.ClientWriteRequestDeleteResponse{
			{
				Status: ofgaclient.SUCCESS,
				Error:  err,
			},
		},
	}

	wi.EXPECT().Execute().Return(&expectedResponse, err)

	wi.EXPECT().Options(mock.Anything).Return(wi)

	wi.EXPECT().Body(mock.Anything).Return(wi)

	c.EXPECT().Write(mock.Anything).Return(wi)
}

// ListAny mocks a list request for any times in a test
func ListAny(t *testing.T, c *MockSdkClient, allowedObjects []string) {
	lr := NewMockSdkClientListObjectsRequestInterface(t)

	resp := ofgaclient.ClientListObjectsResponse{}
	resp.SetObjects(allowedObjects)

	lr.EXPECT().Execute().Return(&resp, nil)

	lr.EXPECT().Body(mock.Anything).Return(lr)

	c.EXPECT().ListObjects(mock.Anything).Return(lr)
}

// ListOnce mocks a list request once with a allowed objects and error if provided
func ListOnce(t *testing.T, c *MockSdkClient, allowedObjects []string, err error) {
	lr := NewMockSdkClientListObjectsRequestInterface(t)

	resp := ofgaclient.ClientListObjectsResponse{}
	resp.SetObjects(allowedObjects)

	lr.EXPECT().Execute().Return(&resp, err)

	lr.EXPECT().Body(mock.Anything).Return(lr)

	c.EXPECT().ListObjects(mock.Anything).Return(lr).Once()
}

// ListOnce mocks a list request once with a allowed objects and error if provided
func ListUsers(t *testing.T, c *MockSdkClient, allowedUsers []openfga.User, err error) {
	lr := NewMockSdkClientListUsersRequestInterface(t)

	resp := ofgaclient.ClientListUsersResponse{}
	resp.SetUsers(allowedUsers)

	lr.EXPECT().Execute().Return(&resp, err)

	lr.EXPECT().Body(mock.Anything).Return(lr)

	c.EXPECT().ListUsers(mock.Anything).Return(lr).Once()
}

// ListTimes mocks a list request for the specified number of times in a test
func ListTimes(t *testing.T, c *MockSdkClient, allowedObjects []string, times int) {
	lr := NewMockSdkClientListObjectsRequestInterface(t)

	resp := ofgaclient.ClientListObjectsResponse{}
	resp.SetObjects(allowedObjects)

	lr.EXPECT().Execute().Return(&resp, nil)

	lr.EXPECT().Body(mock.Anything).Return(lr)

	c.EXPECT().ListObjects(mock.Anything).Return(lr).Times(times)
}

// ReadAny mocks a read request for any times in a test
func ReadAny(t *testing.T, c *MockSdkClient) {
	rr := NewMockSdkClientReadRequestInterface(t)

	rr.EXPECT().Execute().Return(&ofgaclient.ClientReadResponse{}, nil)

	rr.EXPECT().Options(mock.Anything).Return(rr)

	c.EXPECT().Read(mock.Anything).Return(rr)
}

// CheckAny mocks a check request for any times in a test
func CheckAny(t *testing.T, c *MockSdkClient, allowed bool) {
	cr := NewMockSdkClientCheckRequestInterface(t)

	resp := ofgaclient.ClientCheckResponse{
		CheckResponse: openfga.CheckResponse{
			Allowed: openfga.PtrBool(allowed),
		},
	}

	cr.EXPECT().Execute().Return(&resp, nil)

	cr.EXPECT().Body(mock.Anything).Return(cr)

	c.EXPECT().Check(mock.Anything).Return(cr)
}

// CheckAny mocks a check request for any times in a test
func BatchCheck(t *testing.T, c *MockSdkClient, list []string, allowed []string) {
	batch := NewMockSdkClientBatchCheckRequestInterface(t)

	resp := []ofgaclient.ClientBatchCheckSingleResponse{}

	for _, relation := range list {
		result := false
		if slices.Contains(allowed, relation) {
			result = true
		}

		ccr := ofgaclient.ClientCheckResponse{}
		ccr.SetAllowed(result)

		checkResp := ofgaclient.ClientBatchCheckSingleResponse{
			Request: ofgaclient.ClientCheckRequest{
				Relation: relation,
			},
			ClientCheckResponse: ccr,
		}

		resp = append(resp, checkResp)
	}

	batch.EXPECT().Execute().Return(&resp, nil)

	batch.EXPECT().Body(mock.Anything).Return(batch)

	c.EXPECT().BatchCheck(mock.Anything).Return(batch)
}

// DeleteAny creates mock delete responses based on the mock FGA client for
// any times in a test
func DeleteAny(t *testing.T, c *MockSdkClient, errMsg string) {
	di := NewMockSdkClientDeleteTuplesRequestInterface(t)

	var err error
	if errMsg != "" {
		err = errors.New(errMsg) // nolint:err113
	}

	di.EXPECT().Execute().Return(&ofgaclient.ClientWriteResponse{}, err)

	di.EXPECT().Options(mock.Anything).Return(di)

	di.EXPECT().Body(mock.Anything).Return(di)

	c.EXPECT().DeleteTuples(mock.Anything).Return(di)
}
