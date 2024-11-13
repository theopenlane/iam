package testutils

import (
	"context"
	"fmt"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/rs/zerolog/log"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/openfga"
	"github.com/theopenlane/iam/fgax"
)

// Option is a functional configuration option for openFGA client
type Option func(c *OpenFGAConfig)

// OpenFGAConfig configures the openFGA setup
type OpenFGAConfig struct {
	// openFGAVersion is the version of the openFGA container to run, default to latest
	openFGAVersion string
	// modelFile is the path to the model file
	modelFile string
	// storeName of the FGA Store, defaults to a random name if not provided
	storeName string
}

// WithModelFile sets the model file path for the openFGA client
func WithModelFile(modelFile string) Option {
	return func(c *OpenFGAConfig) {
		c.modelFile = modelFile
	}
}

// WithStoreName sets the store name for the openFGA client
func WithStoreName(storeName string) Option {
	return func(c *OpenFGAConfig) {
		c.storeName = storeName
	}
}

// WithVersion sets the version of the openFGA container to run
func WithVersion(version string) Option {
	return func(c *OpenFGAConfig) {
		c.openFGAVersion = version
	}
}

// NewTestFGAClient creates a new fga client with the provided context and options
func NewTestFGAClient(ctx context.Context, opts ...Option) (*fgax.Client, *openfga.OpenFGAContainer, error) {
	// setup the default config
	c := &OpenFGAConfig{
		openFGAVersion: "latest",        // default to latest
		storeName:      gofakeit.Name(), // add a random store name used if not provided
	}

	// apply the options
	for _, opt := range opts {
		opt(c)
	}

	// run the openfga container
	container := fmt.Sprintf("openfga/openfga:%s", c.openFGAVersion)

	openfgaContainer, err := openfga.Run(ctx, container)
	if err != nil {
		log.Error().Err(err).Msg("failed to run openfga container")

		return nil, nil, err
	}

	// create the fga client
	client, err := c.newFgaClient(ctx, openfgaContainer)
	if err != nil {
		log.Error().Err(err).Msg("failed to create fga client")

		return nil, nil, err
	}

	return client, openfgaContainer, nil
}

// newFgaClient creates a new fga client with the provided test container
func (o *OpenFGAConfig) newFgaClient(ctx context.Context, tc *openfga.OpenFGAContainer) (*fgax.Client, error) {
	host, err := tc.HttpEndpoint(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to get host")

		return nil, err
	}

	fgaConfig := fgax.Config{
		StoreName: o.storeName,
		HostURL:   host,
		ModelFile: o.modelFile,
	}

	c, err := fgax.CreateFGAClientWithStore(ctx, fgaConfig)
	if err != nil {
		log.Error().Err(err).Msg("failed to create fga client")

		return nil, err
	}

	return c, nil
}

// TeardownContainer terminates the openFGA container
func TeardownContainer(tc *openfga.OpenFGAContainer) error {
	return testcontainers.TerminateContainer(tc)
}
