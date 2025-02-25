package testutils

import "github.com/testcontainers/testcontainers-go"

const (
	testcontainerName = "tc-openfga"
)

// Customizer type represents a container customizer for transferring state from the options to the container
type Customizer struct {
	reuse bool
	name  string
}

// Customize satisfies the ContainerCustomizer interface
func (c Customizer) Customize(req *testcontainers.GenericContainerRequest) error {
	req.Reuse = c.reuse
	req.Name = c.name

	return nil
}

// WithCustomizer function option to use the customizer
func WithCustomizer(reuse bool, name string) testcontainers.ContainerCustomizer {
	return Customizer{reuse: reuse, name: name}
}
