package testutils

import (
	"github.com/docker/docker/api/types/container"
	"github.com/testcontainers/testcontainers-go"
)

const (
	testcontainerName = "tc-openfga"
)

// Customizer type represents a container customizer for transferring state from the options to the container
type Customizer struct {
	reuse  bool
	name   string
	memory int64
	cpu    int64
}

// Customize satisfies the ContainerCustomizer interface
func (c Customizer) Customize(req *testcontainers.GenericContainerRequest) error {
	req.Reuse = c.reuse
	req.Name = c.name

	req.HostConfigModifier = func(config *container.HostConfig) {
		if c.memory > 0 {
			config.Memory = c.memory
		}

		if c.cpu > 0 {
			config.CPUQuota = c.cpu
		}
	}

	return nil
}

// WithCustomizer function option to use the customizer
func WithCustomizer(reuse bool, name string, memory, cpu int64) testcontainers.ContainerCustomizer {
	return Customizer{
		reuse:  reuse,
		name:   name,
		memory: memory,
		cpu:    cpu,
	}
}
