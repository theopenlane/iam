// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"

	"github.com/theopenlane/iam/entfga/_examples/basic/ent/migrate"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/organization"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/orgmembership"
	"github.com/theopenlane/iam/fgax"

	"github.com/theopenlane/iam/entfga"
)

// Client is the client that holds all ent builders.
type Client struct {
	config
	// Schema is the client for creating, migrating and dropping schema.
	Schema *migrate.Schema
	// OrgMembership is the client for interacting with the OrgMembership builders.
	OrgMembership *OrgMembershipClient
	// Organization is the client for interacting with the Organization builders.
	Organization *OrganizationClient

	// authzActivated determines if the authz hooks have already been activated
	authzActivated bool
}

// NewClient creates a new client configured with the given options.
func NewClient(opts ...Option) *Client {
	client := &Client{config: newConfig(opts...)}
	client.init()
	return client
}

func (c *Client) init() {
	c.Schema = migrate.NewSchema(c.driver)
	c.OrgMembership = NewOrgMembershipClient(c.config)
	c.Organization = NewOrganizationClient(c.config)
}

type (
	// config is the configuration for the client and its builder.
	config struct {
		// driver used for executing database requests.
		driver dialect.Driver
		// debug enable a debug logging.
		debug bool
		// log used for logging on debug mode.
		log func(...any)
		// hooks to execute on mutations.
		hooks *hooks
		// interceptors to execute on queries.
		inters *inters
		Authz  fgax.Client
	}
	// Option function to configure the client.
	Option func(*config)
)

// newConfig creates a new config for the client.
func newConfig(opts ...Option) config {
	cfg := config{log: log.Println, hooks: &hooks{}, inters: &inters{}}
	cfg.options(opts...)
	return cfg
}

// options applies the options on the config object.
func (c *config) options(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
	if c.debug {
		c.driver = dialect.Debug(c.driver, c.log)
	}
}

// Debug enables debug logging on the ent.Driver.
func Debug() Option {
	return func(c *config) {
		c.debug = true
	}
}

// Log sets the logging function for debug mode.
func Log(fn func(...any)) Option {
	return func(c *config) {
		c.log = fn
	}
}

// Driver configures the client driver.
func Driver(driver dialect.Driver) Option {
	return func(c *config) {
		c.driver = driver
	}
}

// Authz configures the Authz.
func Authz(v fgax.Client) Option {
	return func(c *config) {
		c.Authz = v
	}
}

// Open opens a database/sql.DB specified by the driver name and
// the data source name, and returns a new client attached to it.
// Optional parameters can be added for configuring the client.
func Open(driverName, dataSourceName string, options ...Option) (*Client, error) {
	switch driverName {
	case dialect.MySQL, dialect.Postgres, dialect.SQLite:
		drv, err := sql.Open(driverName, dataSourceName)
		if err != nil {
			return nil, err
		}
		return NewClient(append(options, Driver(drv))...), nil
	default:
		return nil, fmt.Errorf("unsupported driver: %q", driverName)
	}
}

// ErrTxStarted is returned when trying to start a new transaction from a transactional client.
var ErrTxStarted = errors.New("ent: cannot start a transaction within a transaction")

// Tx returns a new transactional client. The provided context
// is used until the transaction is committed or rolled back.
func (c *Client) Tx(ctx context.Context) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, ErrTxStarted
	}
	tx, err := newTx(ctx, c.driver)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = tx
	return &Tx{
		ctx:           ctx,
		config:        cfg,
		OrgMembership: NewOrgMembershipClient(cfg),
		Organization:  NewOrganizationClient(cfg),
	}, nil
}

// BeginTx returns a transactional client with specified options.
func (c *Client) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := c.driver.(interface {
		BeginTx(context.Context, *sql.TxOptions) (dialect.Tx, error)
	}).BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = &txDriver{tx: tx, drv: c.driver}
	return &Tx{
		ctx:           ctx,
		config:        cfg,
		OrgMembership: NewOrgMembershipClient(cfg),
		Organization:  NewOrganizationClient(cfg),
	}, nil
}

// Debug returns a new debug-client. It's used to get verbose logging on specific operations.
//
//	client.Debug().
//		OrgMembership.
//		Query().
//		Count(ctx)
func (c *Client) Debug() *Client {
	if c.debug {
		return c
	}
	cfg := c.config
	cfg.driver = dialect.Debug(c.driver, c.log)
	client := &Client{config: cfg}
	client.init()
	return client
}

// Close closes the database connection and prevents new queries from starting.
func (c *Client) Close() error {
	return c.driver.Close()
}

// Use adds the mutation hooks to all the entity clients.
// In order to add hooks to a specific client, call: `client.Node.Use(...)`.
func (c *Client) Use(hooks ...Hook) {
	c.OrgMembership.Use(hooks...)
	c.Organization.Use(hooks...)
}

// Intercept adds the query interceptors to all the entity clients.
// In order to add interceptors to a specific client, call: `client.Node.Intercept(...)`.
func (c *Client) Intercept(interceptors ...Interceptor) {
	c.OrgMembership.Intercept(interceptors...)
	c.Organization.Intercept(interceptors...)
}

// WithAuthz adds the authz hooks to the appropriate schemas - generated by entfga
func (c *Client) WithAuthz() {
	if !c.authzActivated {

		for _, hook := range entfga.AuthzHooks[*OrgMembershipMutation]() {
			c.OrgMembership.Use(hook)
		}

		c.authzActivated = true
	}
}

// Mutate implements the ent.Mutator interface.
func (c *Client) Mutate(ctx context.Context, m Mutation) (Value, error) {
	switch m := m.(type) {
	case *OrgMembershipMutation:
		return c.OrgMembership.mutate(ctx, m)
	case *OrganizationMutation:
		return c.Organization.mutate(ctx, m)
	default:
		return nil, fmt.Errorf("ent: unknown mutation type %T", m)
	}
}

// OrgMembershipClient is a client for the OrgMembership schema.
type OrgMembershipClient struct {
	config
}

// NewOrgMembershipClient returns a client for the OrgMembership from the given config.
func NewOrgMembershipClient(c config) *OrgMembershipClient {
	return &OrgMembershipClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `orgmembership.Hooks(f(g(h())))`.
func (c *OrgMembershipClient) Use(hooks ...Hook) {
	c.hooks.OrgMembership = append(c.hooks.OrgMembership, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `orgmembership.Intercept(f(g(h())))`.
func (c *OrgMembershipClient) Intercept(interceptors ...Interceptor) {
	c.inters.OrgMembership = append(c.inters.OrgMembership, interceptors...)
}

// Create returns a builder for creating a OrgMembership entity.
func (c *OrgMembershipClient) Create() *OrgMembershipCreate {
	mutation := newOrgMembershipMutation(c.config, OpCreate)
	return &OrgMembershipCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of OrgMembership entities.
func (c *OrgMembershipClient) CreateBulk(builders ...*OrgMembershipCreate) *OrgMembershipCreateBulk {
	return &OrgMembershipCreateBulk{config: c.config, builders: builders}
}

// MapCreateBulk creates a bulk creation builder from the given slice. For each item in the slice, the function creates
// a builder and applies setFunc on it.
func (c *OrgMembershipClient) MapCreateBulk(slice any, setFunc func(*OrgMembershipCreate, int)) *OrgMembershipCreateBulk {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return &OrgMembershipCreateBulk{err: fmt.Errorf("calling to OrgMembershipClient.MapCreateBulk with wrong type %T, need slice", slice)}
	}
	builders := make([]*OrgMembershipCreate, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		builders[i] = c.Create()
		setFunc(builders[i], i)
	}
	return &OrgMembershipCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for OrgMembership.
func (c *OrgMembershipClient) Update() *OrgMembershipUpdate {
	mutation := newOrgMembershipMutation(c.config, OpUpdate)
	return &OrgMembershipUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *OrgMembershipClient) UpdateOne(om *OrgMembership) *OrgMembershipUpdateOne {
	mutation := newOrgMembershipMutation(c.config, OpUpdateOne, withOrgMembership(om))
	return &OrgMembershipUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *OrgMembershipClient) UpdateOneID(id string) *OrgMembershipUpdateOne {
	mutation := newOrgMembershipMutation(c.config, OpUpdateOne, withOrgMembershipID(id))
	return &OrgMembershipUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for OrgMembership.
func (c *OrgMembershipClient) Delete() *OrgMembershipDelete {
	mutation := newOrgMembershipMutation(c.config, OpDelete)
	return &OrgMembershipDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *OrgMembershipClient) DeleteOne(om *OrgMembership) *OrgMembershipDeleteOne {
	return c.DeleteOneID(om.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *OrgMembershipClient) DeleteOneID(id string) *OrgMembershipDeleteOne {
	builder := c.Delete().Where(orgmembership.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &OrgMembershipDeleteOne{builder}
}

// Query returns a query builder for OrgMembership.
func (c *OrgMembershipClient) Query() *OrgMembershipQuery {
	return &OrgMembershipQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeOrgMembership},
		inters: c.Interceptors(),
	}
}

// Get returns a OrgMembership entity by its id.
func (c *OrgMembershipClient) Get(ctx context.Context, id string) (*OrgMembership, error) {
	return c.Query().Where(orgmembership.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *OrgMembershipClient) GetX(ctx context.Context, id string) *OrgMembership {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryOrganization queries the organization edge of a OrgMembership.
func (c *OrgMembershipClient) QueryOrganization(om *OrgMembership) *OrganizationQuery {
	query := (&OrganizationClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := om.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(orgmembership.Table, orgmembership.FieldID, id),
			sqlgraph.To(organization.Table, organization.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, orgmembership.OrganizationTable, orgmembership.OrganizationColumn),
		)
		fromV = sqlgraph.Neighbors(om.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *OrgMembershipClient) Hooks() []Hook {
	hooks := c.hooks.OrgMembership
	return append(hooks[:len(hooks):len(hooks)], orgmembership.Hooks[:]...)
}

// Interceptors returns the client interceptors.
func (c *OrgMembershipClient) Interceptors() []Interceptor {
	return c.inters.OrgMembership
}

func (c *OrgMembershipClient) mutate(ctx context.Context, m *OrgMembershipMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&OrgMembershipCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&OrgMembershipUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&OrgMembershipUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&OrgMembershipDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown OrgMembership mutation op: %q", m.Op())
	}
}

// OrganizationClient is a client for the Organization schema.
type OrganizationClient struct {
	config
}

// NewOrganizationClient returns a client for the Organization from the given config.
func NewOrganizationClient(c config) *OrganizationClient {
	return &OrganizationClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `organization.Hooks(f(g(h())))`.
func (c *OrganizationClient) Use(hooks ...Hook) {
	c.hooks.Organization = append(c.hooks.Organization, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `organization.Intercept(f(g(h())))`.
func (c *OrganizationClient) Intercept(interceptors ...Interceptor) {
	c.inters.Organization = append(c.inters.Organization, interceptors...)
}

// Create returns a builder for creating a Organization entity.
func (c *OrganizationClient) Create() *OrganizationCreate {
	mutation := newOrganizationMutation(c.config, OpCreate)
	return &OrganizationCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Organization entities.
func (c *OrganizationClient) CreateBulk(builders ...*OrganizationCreate) *OrganizationCreateBulk {
	return &OrganizationCreateBulk{config: c.config, builders: builders}
}

// MapCreateBulk creates a bulk creation builder from the given slice. For each item in the slice, the function creates
// a builder and applies setFunc on it.
func (c *OrganizationClient) MapCreateBulk(slice any, setFunc func(*OrganizationCreate, int)) *OrganizationCreateBulk {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return &OrganizationCreateBulk{err: fmt.Errorf("calling to OrganizationClient.MapCreateBulk with wrong type %T, need slice", slice)}
	}
	builders := make([]*OrganizationCreate, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		builders[i] = c.Create()
		setFunc(builders[i], i)
	}
	return &OrganizationCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Organization.
func (c *OrganizationClient) Update() *OrganizationUpdate {
	mutation := newOrganizationMutation(c.config, OpUpdate)
	return &OrganizationUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *OrganizationClient) UpdateOne(o *Organization) *OrganizationUpdateOne {
	mutation := newOrganizationMutation(c.config, OpUpdateOne, withOrganization(o))
	return &OrganizationUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *OrganizationClient) UpdateOneID(id string) *OrganizationUpdateOne {
	mutation := newOrganizationMutation(c.config, OpUpdateOne, withOrganizationID(id))
	return &OrganizationUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Organization.
func (c *OrganizationClient) Delete() *OrganizationDelete {
	mutation := newOrganizationMutation(c.config, OpDelete)
	return &OrganizationDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *OrganizationClient) DeleteOne(o *Organization) *OrganizationDeleteOne {
	return c.DeleteOneID(o.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *OrganizationClient) DeleteOneID(id string) *OrganizationDeleteOne {
	builder := c.Delete().Where(organization.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &OrganizationDeleteOne{builder}
}

// Query returns a query builder for Organization.
func (c *OrganizationClient) Query() *OrganizationQuery {
	return &OrganizationQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeOrganization},
		inters: c.Interceptors(),
	}
}

// Get returns a Organization entity by its id.
func (c *OrganizationClient) Get(ctx context.Context, id string) (*Organization, error) {
	return c.Query().Where(organization.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *OrganizationClient) GetX(ctx context.Context, id string) *Organization {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// Hooks returns the client hooks.
func (c *OrganizationClient) Hooks() []Hook {
	hooks := c.hooks.Organization
	return append(hooks[:len(hooks):len(hooks)], organization.Hooks[:]...)
}

// Interceptors returns the client interceptors.
func (c *OrganizationClient) Interceptors() []Interceptor {
	return c.inters.Organization
}

func (c *OrganizationClient) mutate(ctx context.Context, m *OrganizationMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&OrganizationCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&OrganizationUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&OrganizationUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&OrganizationDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown Organization mutation op: %q", m.Op())
	}
}

// hooks and interceptors per client, for fast access.
type (
	hooks struct {
		OrgMembership, Organization []ent.Hook
	}
	inters struct {
		OrgMembership, Organization []ent.Interceptor
	}
)
