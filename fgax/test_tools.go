package fgax

import (
	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"

	mock_fga "github.com/theopenlane/iam/fgax/internal/mockery"
)

// NewMockFGAClient is a mock client based on the mockery testing framework
func NewMockFGAClient(c *mock_fga.MockSdkClient) *Client {
	client := Client{
		Config: ofgaclient.ClientConfiguration{
			// The api host is the only required field when setting up a new FGA client connection
			ApiHost:              "fga.theopenlane.io",
			AuthorizationModelId: *openfga.PtrString("test-model-id"),
			StoreId:              *openfga.PtrString("test-store-id"),
		},
		Ofga: c,
	}

	return &client
}
