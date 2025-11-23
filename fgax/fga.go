package fgax

import (
	"context"

	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/rs/zerolog/log"
)

// Client is an ofga client with some configuration
type Client struct {
	// Ofga is the openFGA client
	Ofga ofgaclient.SdkClient
	// Config is the client configuration
	Config ofgaclient.ClientConfiguration
	// MaxBatchWriteSize is the maximum number of writes per batch in a transaction, default 100
	MaxBatchWriteSize int
}

// Config configures the openFGA setup
type Config struct {
	// Enabled - checks this first before reading the config
	Enabled bool `json:"enabled" koanf:"enabled" jsonschema:"description=enables authorization checks with openFGA" default:"true"`
	// StoreName of the FGA Store
	StoreName string `json:"storename" koanf:"storename" jsonschema:"description=name of openFGA store" default:"openlane"`
	// HostURL of the fga API, replaces Host and Scheme settings
	HostURL string `json:"hosturl" koanf:"hosturl" jsonschema:"description=host url with scheme of the openFGA API,required" default:"https://authz.theopenlane.io"`
	// StoreID of the authorization store in FGA
	StoreID string `json:"storeid" koanf:"storeid" jsonschema:"description=id of openFGA store"`
	// ModelID that already exists in authorization store to be used
	ModelID string `json:"modelid" koanf:"modelid" jsonschema:"description=id of openFGA model"`
	// CreateNewModel force creates a new model, even if one already exists
	CreateNewModel bool `json:"createnewmodel" koanf:"createnewmodel" jsonschema:"description=force create a new model, even if one already exists" default:"false"`
	// ModelFile is the path to the model file
	ModelFile string `json:"modelfile" koanf:"modelfile" jsonschema:"description=path to the fga model file" default:"fga/model/model.fga"`
	// Credentials for the client
	Credentials Credentials `json:"credentials" koanf:"credentials" jsonschema:"description=credentials for the openFGA client"`
	// MaxBatchWriteSize is the maximum number of writes per batch in a transaction, default 100
	MaxBatchWriteSize int `json:"maxbatchwritesize" koanf:"maxbatchwritesize" jsonschema:"description=maximum number of writes per batch in a transaction, defaults to 100" default:"100"`
}

// Credentials for the openFGA client
type Credentials struct {
	// APIToken is the token to use for the client, required if using API token authentication
	APIToken string `json:"apitoken" koanf:"apitoken" jsonschema:"description=api token for the openFGA client, required if using pre-shared key authentication" sensitive:"true"`
	// ClientID is the client ID to use for the client, required if using client credentials
	ClientID string `json:"clientid" koanf:"clientid" jsonschema:"description=client id for the openFGA client, required if using client credentials authentication"`
	// ClientSecret is the client secret to use for the client, required if using client credentials
	ClientSecret string `json:"clientsecret" koanf:"clientsecret" jsonschema:"description=client secret for the openFGA client, required if using client credentials authentication" sensitive:"true"`
	// Audience is the audience to use for the client, required if using client credentials
	Audience string `json:"audience" koanf:"audience" jsonschema:"description=audience for the openFGA client"`
	// Issuer is the issuer to use for the client, required if using client credentials
	Issuer string `json:"issuer" koanf:"issuer" jsonschema:"description=issuer for the openFGA client"`
	// Scopes is the scopes to use for the client, required if using client credentials
	Scopes string `json:"scopes" koanf:"scopes" jsonschema:"description=scopes for the openFGA client"`
}

// Option is a functional configuration option for openFGA client
type Option func(c *Client)

// NewClient returns a wrapped OpenFGA API client ensuring all calls are made
// to the provided authorization model (id) and returns what is necessary.
func NewClient(host string, opts ...Option) (*Client, error) {
	if host == "" {
		return nil, ErrFGAMissingHost
	}

	// The api host is the only required field when setting up a new FGA client connection
	client := Client{
		Config: ofgaclient.ClientConfiguration{
			ApiUrl: host,
		},
	}

	for _, opt := range opts {
		opt(&client)
	}

	fgaClient, err := ofgaclient.NewSdkClient(&client.Config)
	if err != nil {
		return nil, err
	}

	client.Ofga = fgaClient

	return &client, err
}

func (c *Client) GetModelID() string {
	return c.Config.AuthorizationModelId
}

// WithStoreID sets the store IDs, not needed when calling `CreateStore` or `ListStores`
func WithStoreID(storeID string) Option {
	return func(c *Client) {
		c.Config.StoreId = storeID
	}
}

// WithAuthorizationModelID sets the authorization model ID
func WithAuthorizationModelID(authModelID string) Option {
	return func(c *Client) {
		c.Config.AuthorizationModelId = authModelID
	}
}

// WithAPITokenCredentials sets the credentials for the client with an API token
func WithAPITokenCredentials(token string) Option {
	return func(c *Client) {
		c.Config.Credentials = &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{
				ApiToken: token,
			},
		}
	}
}

// WithClientCredentials sets the client credentials for the client with a client ID and secret
func WithClientCredentials(clientID, clientSecret, aud, issuer, scopes string) Option {
	return func(c *Client) {
		c.Config.Credentials = &credentials.Credentials{
			Method: credentials.CredentialsMethodClientCredentials,
			Config: &credentials.Config{
				ClientCredentialsClientId:       clientID,
				ClientCredentialsClientSecret:   clientSecret,
				ClientCredentialsApiAudience:    aud,
				ClientCredentialsApiTokenIssuer: issuer,
				ClientCredentialsScopes:         scopes,
			},
		}
	}
}

// WithToken sets the client credentials
func WithToken(token string) Option {
	return func(c *Client) {
		c.Config.Credentials = &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{
				ApiToken: token,
			},
		}
	}
}

// CreateFGAClientWithStore returns a Client with a store and model configured
func CreateFGAClientWithStore(ctx context.Context, c Config) (*Client, error) {
	opts := []Option{}

	// set credentials if provided
	if c.Credentials.APIToken != "" {
		opts = append(opts, WithAPITokenCredentials(c.Credentials.APIToken))
	} else if c.Credentials.ClientID != "" && c.Credentials.ClientSecret != "" {
		opts = append(opts, WithClientCredentials(
			c.Credentials.ClientID,
			c.Credentials.ClientSecret,
			c.Credentials.Audience,
			c.Credentials.Issuer,
			c.Credentials.Scopes,
		))
	}

	// create store if an ID was not configured
	if c.StoreID == "" {
		// Create new store
		fgaClient, err := NewClient(
			c.HostURL,
			opts...,
		)
		if err != nil {
			return nil, err
		}

		c.StoreID, err = fgaClient.CreateStore(ctx, c.StoreName)
		if err != nil {
			return nil, err
		}
	}

	// add store ID to the options
	opts = append(opts, WithStoreID(c.StoreID))

	// create model if ID was not configured
	if c.ModelID == "" {
		// create fga client with store ID
		fgaClient, err := NewClient(
			c.HostURL,
			opts...,
		)
		if err != nil {
			return nil, err
		}

		// Create model if one does not already exist
		modelID, err := fgaClient.CreateModelFromFile(ctx, c.ModelFile, c.CreateNewModel)
		if err != nil {
			return nil, err
		}

		// Set ModelID in the config
		c.ModelID = modelID
	}

	// add model ID to the options
	opts = append(opts,
		WithAuthorizationModelID(c.ModelID),
	)

	// create fga client with store ID
	client, err := NewClient(
		c.HostURL,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	// set max batch write size
	client.MaxBatchWriteSize = c.MaxBatchWriteSize
	if client.MaxBatchWriteSize == 0 {
		client.MaxBatchWriteSize = defaultMaxWriteBatchSize
	}

	return client, nil
}

// CreateStore creates a new fine grained authorization store and returns the store ID
func (c *Client) CreateStore(ctx context.Context, storeName string) (string, error) {
	options := ofgaclient.ClientListStoresOptions{
		ContinuationToken: openfga.PtrString(""),
	}

	stores, err := c.Ofga.ListStores(ctx).Options(options).Execute()
	if err != nil {
		return "", err
	}

	// Only create a new test store if one does not exist
	if len(stores.GetStores()) > 0 {
		storeID := stores.GetStores()[0].Id
		log.Info().Str("store_id", storeID).Msg("fga store exists")

		return storeID, nil
	}

	// Create new store
	storeReq := c.Ofga.CreateStore(ctx)

	resp, err := storeReq.Body(ofgaclient.ClientCreateStoreRequest{
		Name: storeName,
	}).Execute()
	if err != nil {
		return "", err
	}

	storeID := resp.GetId()

	log.Info().Str("store_id", storeID).Msg("fga store created")

	return storeID, nil
}

// Healthcheck reads the model to check if the connection is working
func Healthcheck(client Client) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := ofgaclient.ClientReadAuthorizationModelOptions{
			AuthorizationModelId: &client.Config.AuthorizationModelId,
		}

		_, err := client.Ofga.ReadAuthorizationModel(ctx).Options(opts).Execute()
		if err != nil {
			return err
		}

		return nil
	}
}
