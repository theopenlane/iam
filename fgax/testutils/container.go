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
type Option func(c *OpenFGATestFixture)

// OpenFGATestFixture configures the openFGA setup for testing
type OpenFGATestFixture struct {
	// openFGAVersion is the version of the openFGA container to run, default to latest
	openFGAVersion string
	// modelFile is the path to the model file
	modelFile string
	// storeName of the FGA Store, defaults to a random name if not provided
	storeName string
	// tf is the openFGA test fixture
	tf *openfga.OpenFGAContainer
	// reuse is a flag to reuse the container
	reuse bool
	// containerName is the name of the container, defaults to tc-openfga when reusing containers
	containerName string
	// memory is the memory for the container
	memory int64
	// cpu is the CPU for the container
	cpu int64
	// envVars is a map of environment variables to set in the container
	envVars map[string]string
}

// WithModelFile sets the model file path for the openFGA client
func WithModelFile(modelFile string) Option {
	return func(c *OpenFGATestFixture) {
		c.modelFile = modelFile
	}
}

// WithStoreName sets the store name for the openFGA client
func WithStoreName(storeName string) Option {
	return func(c *OpenFGATestFixture) {
		c.storeName = storeName
	}
}

// WithVersion sets the version of the openFGA container to run
func WithVersion(version string) Option {
	return func(c *OpenFGATestFixture) {
		c.openFGAVersion = version
	}
}

// WithReuse allows the container to be reused
func WithReuse(reuse bool) Option {
	return func(c *OpenFGATestFixture) {
		c.reuse = reuse
	}
}

// WithContainerName allows the container name to be set when using reusable containers
func WithContainerName(name string) Option {
	return func(c *OpenFGATestFixture) {
		c.containerName = name
	}
}

// WithMemory sets the memory for the openFGA container
func WithMemory(memory int64) Option {
	return func(c *OpenFGATestFixture) {
		c.memory = memory
	}
}

// WithCPU sets the CPU for the openFGA container
func WithCPU(cpu int64) Option {
	return func(c *OpenFGATestFixture) {
		c.cpu = cpu
	}
}

// WithEnvVars sets the environment variables for the openFGA container
func WithEnvVars(envVars map[string]string) Option {
	return func(c *OpenFGATestFixture) {
		c.envVars = envVars
	}
}

// NewFGATestcontainer creates a new test container with the provided context and options
func NewFGATestcontainer(ctx context.Context, opts ...Option) *OpenFGATestFixture {
	// setup the default config
	c := &OpenFGATestFixture{
		openFGAVersion: "latest",        // default to latest
		storeName:      gofakeit.Name(), // add a random store name used if not provided
	}

	// apply the options
	for _, opt := range opts {
		opt(c)
	}

	if c.reuse && c.containerName == "" {
		c.containerName = testcontainerName // default to tc-openfga when reusing containers and no name is provided
	}

	// run the openfga container
	container := fmt.Sprintf("openfga/openfga:%s", c.openFGAVersion)

	openfgaContainer, err := openfga.Run(
		ctx,
		container,
		WithCustomizer(c.reuse, c.containerName, c.memory, c.cpu),
		testcontainers.WithEnv(c.envVars),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to run openfga container")
	}

	c.tf = openfgaContainer

	return c
}

// NewFgaClient creates a new fga client with the provided test container
func (o *OpenFGATestFixture) NewFgaClient(ctx context.Context) (*fgax.Client, error) {
	host, err := o.tf.HttpEndpoint(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to get host")

		return nil, err
	}

	fgaConfig := fgax.Config{
		StoreName:               o.storeName,
		HostURL:                 host,
		ModelFile:               o.modelFile,
		IgnoreDuplicateKeyError: true,
	}

	c, err := fgax.CreateFGAClientWithStore(ctx, fgaConfig)
	if err != nil {
		log.Error().Err(err).Msg("failed to create fga client")

		return nil, err
	}

	return c, nil
}

// TeardownFixture terminates the openFGA container
func (o *OpenFGATestFixture) TeardownFixture() error {
	return testcontainers.TerminateContainer(o.tf.Container)
}
