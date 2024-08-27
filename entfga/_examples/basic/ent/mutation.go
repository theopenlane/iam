// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/enums"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/organization"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/orgmembership"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/predicate"
)

const (
	// Operation types.
	OpCreate    = ent.OpCreate
	OpDelete    = ent.OpDelete
	OpDeleteOne = ent.OpDeleteOne
	OpUpdate    = ent.OpUpdate
	OpUpdateOne = ent.OpUpdateOne

	// Node types.
	TypeOrgMembership = "OrgMembership"
	TypeOrganization  = "Organization"
)

// OrgMembershipMutation represents an operation that mutates the OrgMembership nodes in the graph.
type OrgMembershipMutation struct {
	config
	op                  Op
	typ                 string
	id                  *string
	role                *enums.Role
	user_id             *string
	clearedFields       map[string]struct{}
	organization        *string
	clearedorganization bool
	done                bool
	oldValue            func(context.Context) (*OrgMembership, error)
	predicates          []predicate.OrgMembership
}

var _ ent.Mutation = (*OrgMembershipMutation)(nil)

// orgmembershipOption allows management of the mutation configuration using functional options.
type orgmembershipOption func(*OrgMembershipMutation)

// newOrgMembershipMutation creates new mutation for the OrgMembership entity.
func newOrgMembershipMutation(c config, op Op, opts ...orgmembershipOption) *OrgMembershipMutation {
	m := &OrgMembershipMutation{
		config:        c,
		op:            op,
		typ:           TypeOrgMembership,
		clearedFields: make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// withOrgMembershipID sets the ID field of the mutation.
func withOrgMembershipID(id string) orgmembershipOption {
	return func(m *OrgMembershipMutation) {
		var (
			err   error
			once  sync.Once
			value *OrgMembership
		)
		m.oldValue = func(ctx context.Context) (*OrgMembership, error) {
			once.Do(func() {
				if m.done {
					err = errors.New("querying old values post mutation is not allowed")
				} else {
					value, err = m.Client().OrgMembership.Get(ctx, id)
				}
			})
			return value, err
		}
		m.id = &id
	}
}

// withOrgMembership sets the old OrgMembership of the mutation.
func withOrgMembership(node *OrgMembership) orgmembershipOption {
	return func(m *OrgMembershipMutation) {
		m.oldValue = func(context.Context) (*OrgMembership, error) {
			return node, nil
		}
		m.id = &node.ID
	}
}

// Client returns a new `ent.Client` from the mutation. If the mutation was
// executed in a transaction (ent.Tx), a transactional client is returned.
func (m OrgMembershipMutation) Client() *Client {
	client := &Client{config: m.config}
	client.init()
	return client
}

// Tx returns an `ent.Tx` for mutations that were executed in transactions;
// it returns an error otherwise.
func (m OrgMembershipMutation) Tx() (*Tx, error) {
	if _, ok := m.driver.(*txDriver); !ok {
		return nil, errors.New("ent: mutation is not running in a transaction")
	}
	tx := &Tx{config: m.config}
	tx.init()
	return tx, nil
}

// SetID sets the value of the id field. Note that this
// operation is only accepted on creation of OrgMembership entities.
func (m *OrgMembershipMutation) SetID(id string) {
	m.id = &id
}

// ID returns the ID value in the mutation. Note that the ID is only available
// if it was provided to the builder or after it was returned from the database.
func (m *OrgMembershipMutation) ID() (id string, exists bool) {
	if m.id == nil {
		return
	}
	return *m.id, true
}

// IDs queries the database and returns the entity ids that match the mutation's predicate.
// That means, if the mutation is applied within a transaction with an isolation level such
// as sql.LevelSerializable, the returned ids match the ids of the rows that will be updated
// or updated by the mutation.
func (m *OrgMembershipMutation) IDs(ctx context.Context) ([]string, error) {
	switch {
	case m.op.Is(OpUpdateOne | OpDeleteOne):
		id, exists := m.ID()
		if exists {
			return []string{id}, nil
		}
		fallthrough
	case m.op.Is(OpUpdate | OpDelete):
		return m.Client().OrgMembership.Query().Where(m.predicates...).IDs(ctx)
	default:
		return nil, fmt.Errorf("IDs is not allowed on %s operations", m.op)
	}
}

// SetRole sets the "role" field.
func (m *OrgMembershipMutation) SetRole(e enums.Role) {
	m.role = &e
}

// Role returns the value of the "role" field in the mutation.
func (m *OrgMembershipMutation) Role() (r enums.Role, exists bool) {
	v := m.role
	if v == nil {
		return
	}
	return *v, true
}

// OldRole returns the old "role" field's value of the OrgMembership entity.
// If the OrgMembership object wasn't provided to the builder, the object is fetched from the database.
// An error is returned if the mutation operation is not UpdateOne, or the database query fails.
func (m *OrgMembershipMutation) OldRole(ctx context.Context) (v enums.Role, err error) {
	if !m.op.Is(OpUpdateOne) {
		return v, errors.New("OldRole is only allowed on UpdateOne operations")
	}
	if m.id == nil || m.oldValue == nil {
		return v, errors.New("OldRole requires an ID field in the mutation")
	}
	oldValue, err := m.oldValue(ctx)
	if err != nil {
		return v, fmt.Errorf("querying old value for OldRole: %w", err)
	}
	return oldValue.Role, nil
}

// ResetRole resets all changes to the "role" field.
func (m *OrgMembershipMutation) ResetRole() {
	m.role = nil
}

// SetOrganizationID sets the "organization_id" field.
func (m *OrgMembershipMutation) SetOrganizationID(s string) {
	m.organization = &s
}

// OrganizationID returns the value of the "organization_id" field in the mutation.
func (m *OrgMembershipMutation) OrganizationID() (r string, exists bool) {
	v := m.organization
	if v == nil {
		return
	}
	return *v, true
}

// OldOrganizationID returns the old "organization_id" field's value of the OrgMembership entity.
// If the OrgMembership object wasn't provided to the builder, the object is fetched from the database.
// An error is returned if the mutation operation is not UpdateOne, or the database query fails.
func (m *OrgMembershipMutation) OldOrganizationID(ctx context.Context) (v string, err error) {
	if !m.op.Is(OpUpdateOne) {
		return v, errors.New("OldOrganizationID is only allowed on UpdateOne operations")
	}
	if m.id == nil || m.oldValue == nil {
		return v, errors.New("OldOrganizationID requires an ID field in the mutation")
	}
	oldValue, err := m.oldValue(ctx)
	if err != nil {
		return v, fmt.Errorf("querying old value for OldOrganizationID: %w", err)
	}
	return oldValue.OrganizationID, nil
}

// ResetOrganizationID resets all changes to the "organization_id" field.
func (m *OrgMembershipMutation) ResetOrganizationID() {
	m.organization = nil
}

// SetUserID sets the "user_id" field.
func (m *OrgMembershipMutation) SetUserID(s string) {
	m.user_id = &s
}

// UserID returns the value of the "user_id" field in the mutation.
func (m *OrgMembershipMutation) UserID() (r string, exists bool) {
	v := m.user_id
	if v == nil {
		return
	}
	return *v, true
}

// OldUserID returns the old "user_id" field's value of the OrgMembership entity.
// If the OrgMembership object wasn't provided to the builder, the object is fetched from the database.
// An error is returned if the mutation operation is not UpdateOne, or the database query fails.
func (m *OrgMembershipMutation) OldUserID(ctx context.Context) (v string, err error) {
	if !m.op.Is(OpUpdateOne) {
		return v, errors.New("OldUserID is only allowed on UpdateOne operations")
	}
	if m.id == nil || m.oldValue == nil {
		return v, errors.New("OldUserID requires an ID field in the mutation")
	}
	oldValue, err := m.oldValue(ctx)
	if err != nil {
		return v, fmt.Errorf("querying old value for OldUserID: %w", err)
	}
	return oldValue.UserID, nil
}

// ResetUserID resets all changes to the "user_id" field.
func (m *OrgMembershipMutation) ResetUserID() {
	m.user_id = nil
}

// ClearOrganization clears the "organization" edge to the Organization entity.
func (m *OrgMembershipMutation) ClearOrganization() {
	m.clearedorganization = true
	m.clearedFields[orgmembership.FieldOrganizationID] = struct{}{}
}

// OrganizationCleared reports if the "organization" edge to the Organization entity was cleared.
func (m *OrgMembershipMutation) OrganizationCleared() bool {
	return m.clearedorganization
}

// OrganizationIDs returns the "organization" edge IDs in the mutation.
// Note that IDs always returns len(IDs) <= 1 for unique edges, and you should use
// OrganizationID instead. It exists only for internal usage by the builders.
func (m *OrgMembershipMutation) OrganizationIDs() (ids []string) {
	if id := m.organization; id != nil {
		ids = append(ids, *id)
	}
	return
}

// ResetOrganization resets all changes to the "organization" edge.
func (m *OrgMembershipMutation) ResetOrganization() {
	m.organization = nil
	m.clearedorganization = false
}

// Where appends a list predicates to the OrgMembershipMutation builder.
func (m *OrgMembershipMutation) Where(ps ...predicate.OrgMembership) {
	m.predicates = append(m.predicates, ps...)
}

// WhereP appends storage-level predicates to the OrgMembershipMutation builder. Using this method,
// users can use type-assertion to append predicates that do not depend on any generated package.
func (m *OrgMembershipMutation) WhereP(ps ...func(*sql.Selector)) {
	p := make([]predicate.OrgMembership, len(ps))
	for i := range ps {
		p[i] = ps[i]
	}
	m.Where(p...)
}

// Op returns the operation name.
func (m *OrgMembershipMutation) Op() Op {
	return m.op
}

// SetOp allows setting the mutation operation.
func (m *OrgMembershipMutation) SetOp(op Op) {
	m.op = op
}

// Type returns the node type of this mutation (OrgMembership).
func (m *OrgMembershipMutation) Type() string {
	return m.typ
}

// Fields returns all fields that were changed during this mutation. Note that in
// order to get all numeric fields that were incremented/decremented, call
// AddedFields().
func (m *OrgMembershipMutation) Fields() []string {
	fields := make([]string, 0, 3)
	if m.role != nil {
		fields = append(fields, orgmembership.FieldRole)
	}
	if m.organization != nil {
		fields = append(fields, orgmembership.FieldOrganizationID)
	}
	if m.user_id != nil {
		fields = append(fields, orgmembership.FieldUserID)
	}
	return fields
}

// Field returns the value of a field with the given name. The second boolean
// return value indicates that this field was not set, or was not defined in the
// schema.
func (m *OrgMembershipMutation) Field(name string) (ent.Value, bool) {
	switch name {
	case orgmembership.FieldRole:
		return m.Role()
	case orgmembership.FieldOrganizationID:
		return m.OrganizationID()
	case orgmembership.FieldUserID:
		return m.UserID()
	}
	return nil, false
}

// OldField returns the old value of the field from the database. An error is
// returned if the mutation operation is not UpdateOne, or the query to the
// database failed.
func (m *OrgMembershipMutation) OldField(ctx context.Context, name string) (ent.Value, error) {
	switch name {
	case orgmembership.FieldRole:
		return m.OldRole(ctx)
	case orgmembership.FieldOrganizationID:
		return m.OldOrganizationID(ctx)
	case orgmembership.FieldUserID:
		return m.OldUserID(ctx)
	}
	return nil, fmt.Errorf("unknown OrgMembership field %s", name)
}

// SetField sets the value of a field with the given name. It returns an error if
// the field is not defined in the schema, or if the type mismatched the field
// type.
func (m *OrgMembershipMutation) SetField(name string, value ent.Value) error {
	switch name {
	case orgmembership.FieldRole:
		v, ok := value.(enums.Role)
		if !ok {
			return fmt.Errorf("unexpected type %T for field %s", value, name)
		}
		m.SetRole(v)
		return nil
	case orgmembership.FieldOrganizationID:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("unexpected type %T for field %s", value, name)
		}
		m.SetOrganizationID(v)
		return nil
	case orgmembership.FieldUserID:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("unexpected type %T for field %s", value, name)
		}
		m.SetUserID(v)
		return nil
	}
	return fmt.Errorf("unknown OrgMembership field %s", name)
}

// AddedFields returns all numeric fields that were incremented/decremented during
// this mutation.
func (m *OrgMembershipMutation) AddedFields() []string {
	return nil
}

// AddedField returns the numeric value that was incremented/decremented on a field
// with the given name. The second boolean return value indicates that this field
// was not set, or was not defined in the schema.
func (m *OrgMembershipMutation) AddedField(name string) (ent.Value, bool) {
	return nil, false
}

// AddField adds the value to the field with the given name. It returns an error if
// the field is not defined in the schema, or if the type mismatched the field
// type.
func (m *OrgMembershipMutation) AddField(name string, value ent.Value) error {
	switch name {
	}
	return fmt.Errorf("unknown OrgMembership numeric field %s", name)
}

// ClearedFields returns all nullable fields that were cleared during this
// mutation.
func (m *OrgMembershipMutation) ClearedFields() []string {
	return nil
}

// FieldCleared returns a boolean indicating if a field with the given name was
// cleared in this mutation.
func (m *OrgMembershipMutation) FieldCleared(name string) bool {
	_, ok := m.clearedFields[name]
	return ok
}

// ClearField clears the value of the field with the given name. It returns an
// error if the field is not defined in the schema.
func (m *OrgMembershipMutation) ClearField(name string) error {
	return fmt.Errorf("unknown OrgMembership nullable field %s", name)
}

// ResetField resets all changes in the mutation for the field with the given name.
// It returns an error if the field is not defined in the schema.
func (m *OrgMembershipMutation) ResetField(name string) error {
	switch name {
	case orgmembership.FieldRole:
		m.ResetRole()
		return nil
	case orgmembership.FieldOrganizationID:
		m.ResetOrganizationID()
		return nil
	case orgmembership.FieldUserID:
		m.ResetUserID()
		return nil
	}
	return fmt.Errorf("unknown OrgMembership field %s", name)
}

// AddedEdges returns all edge names that were set/added in this mutation.
func (m *OrgMembershipMutation) AddedEdges() []string {
	edges := make([]string, 0, 1)
	if m.organization != nil {
		edges = append(edges, orgmembership.EdgeOrganization)
	}
	return edges
}

// AddedIDs returns all IDs (to other nodes) that were added for the given edge
// name in this mutation.
func (m *OrgMembershipMutation) AddedIDs(name string) []ent.Value {
	switch name {
	case orgmembership.EdgeOrganization:
		if id := m.organization; id != nil {
			return []ent.Value{*id}
		}
	}
	return nil
}

// RemovedEdges returns all edge names that were removed in this mutation.
func (m *OrgMembershipMutation) RemovedEdges() []string {
	edges := make([]string, 0, 1)
	return edges
}

// RemovedIDs returns all IDs (to other nodes) that were removed for the edge with
// the given name in this mutation.
func (m *OrgMembershipMutation) RemovedIDs(name string) []ent.Value {
	return nil
}

// ClearedEdges returns all edge names that were cleared in this mutation.
func (m *OrgMembershipMutation) ClearedEdges() []string {
	edges := make([]string, 0, 1)
	if m.clearedorganization {
		edges = append(edges, orgmembership.EdgeOrganization)
	}
	return edges
}

// EdgeCleared returns a boolean which indicates if the edge with the given name
// was cleared in this mutation.
func (m *OrgMembershipMutation) EdgeCleared(name string) bool {
	switch name {
	case orgmembership.EdgeOrganization:
		return m.clearedorganization
	}
	return false
}

// ClearEdge clears the value of the edge with the given name. It returns an error
// if that edge is not defined in the schema.
func (m *OrgMembershipMutation) ClearEdge(name string) error {
	switch name {
	case orgmembership.EdgeOrganization:
		m.ClearOrganization()
		return nil
	}
	return fmt.Errorf("unknown OrgMembership unique edge %s", name)
}

// ResetEdge resets all changes to the edge with the given name in this mutation.
// It returns an error if the edge is not defined in the schema.
func (m *OrgMembershipMutation) ResetEdge(name string) error {
	switch name {
	case orgmembership.EdgeOrganization:
		m.ResetOrganization()
		return nil
	}
	return fmt.Errorf("unknown OrgMembership edge %s", name)
}

// OrganizationMutation represents an operation that mutates the Organization nodes in the graph.
type OrganizationMutation struct {
	config
	op            Op
	typ           string
	id            *string
	name          *string
	description   *string
	clearedFields map[string]struct{}
	done          bool
	oldValue      func(context.Context) (*Organization, error)
	predicates    []predicate.Organization
}

var _ ent.Mutation = (*OrganizationMutation)(nil)

// organizationOption allows management of the mutation configuration using functional options.
type organizationOption func(*OrganizationMutation)

// newOrganizationMutation creates new mutation for the Organization entity.
func newOrganizationMutation(c config, op Op, opts ...organizationOption) *OrganizationMutation {
	m := &OrganizationMutation{
		config:        c,
		op:            op,
		typ:           TypeOrganization,
		clearedFields: make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// withOrganizationID sets the ID field of the mutation.
func withOrganizationID(id string) organizationOption {
	return func(m *OrganizationMutation) {
		var (
			err   error
			once  sync.Once
			value *Organization
		)
		m.oldValue = func(ctx context.Context) (*Organization, error) {
			once.Do(func() {
				if m.done {
					err = errors.New("querying old values post mutation is not allowed")
				} else {
					value, err = m.Client().Organization.Get(ctx, id)
				}
			})
			return value, err
		}
		m.id = &id
	}
}

// withOrganization sets the old Organization of the mutation.
func withOrganization(node *Organization) organizationOption {
	return func(m *OrganizationMutation) {
		m.oldValue = func(context.Context) (*Organization, error) {
			return node, nil
		}
		m.id = &node.ID
	}
}

// Client returns a new `ent.Client` from the mutation. If the mutation was
// executed in a transaction (ent.Tx), a transactional client is returned.
func (m OrganizationMutation) Client() *Client {
	client := &Client{config: m.config}
	client.init()
	return client
}

// Tx returns an `ent.Tx` for mutations that were executed in transactions;
// it returns an error otherwise.
func (m OrganizationMutation) Tx() (*Tx, error) {
	if _, ok := m.driver.(*txDriver); !ok {
		return nil, errors.New("ent: mutation is not running in a transaction")
	}
	tx := &Tx{config: m.config}
	tx.init()
	return tx, nil
}

// SetID sets the value of the id field. Note that this
// operation is only accepted on creation of Organization entities.
func (m *OrganizationMutation) SetID(id string) {
	m.id = &id
}

// ID returns the ID value in the mutation. Note that the ID is only available
// if it was provided to the builder or after it was returned from the database.
func (m *OrganizationMutation) ID() (id string, exists bool) {
	if m.id == nil {
		return
	}
	return *m.id, true
}

// IDs queries the database and returns the entity ids that match the mutation's predicate.
// That means, if the mutation is applied within a transaction with an isolation level such
// as sql.LevelSerializable, the returned ids match the ids of the rows that will be updated
// or updated by the mutation.
func (m *OrganizationMutation) IDs(ctx context.Context) ([]string, error) {
	switch {
	case m.op.Is(OpUpdateOne | OpDeleteOne):
		id, exists := m.ID()
		if exists {
			return []string{id}, nil
		}
		fallthrough
	case m.op.Is(OpUpdate | OpDelete):
		return m.Client().Organization.Query().Where(m.predicates...).IDs(ctx)
	default:
		return nil, fmt.Errorf("IDs is not allowed on %s operations", m.op)
	}
}

// SetName sets the "name" field.
func (m *OrganizationMutation) SetName(s string) {
	m.name = &s
}

// Name returns the value of the "name" field in the mutation.
func (m *OrganizationMutation) Name() (r string, exists bool) {
	v := m.name
	if v == nil {
		return
	}
	return *v, true
}

// OldName returns the old "name" field's value of the Organization entity.
// If the Organization object wasn't provided to the builder, the object is fetched from the database.
// An error is returned if the mutation operation is not UpdateOne, or the database query fails.
func (m *OrganizationMutation) OldName(ctx context.Context) (v string, err error) {
	if !m.op.Is(OpUpdateOne) {
		return v, errors.New("OldName is only allowed on UpdateOne operations")
	}
	if m.id == nil || m.oldValue == nil {
		return v, errors.New("OldName requires an ID field in the mutation")
	}
	oldValue, err := m.oldValue(ctx)
	if err != nil {
		return v, fmt.Errorf("querying old value for OldName: %w", err)
	}
	return oldValue.Name, nil
}

// ResetName resets all changes to the "name" field.
func (m *OrganizationMutation) ResetName() {
	m.name = nil
}

// SetDescription sets the "description" field.
func (m *OrganizationMutation) SetDescription(s string) {
	m.description = &s
}

// Description returns the value of the "description" field in the mutation.
func (m *OrganizationMutation) Description() (r string, exists bool) {
	v := m.description
	if v == nil {
		return
	}
	return *v, true
}

// OldDescription returns the old "description" field's value of the Organization entity.
// If the Organization object wasn't provided to the builder, the object is fetched from the database.
// An error is returned if the mutation operation is not UpdateOne, or the database query fails.
func (m *OrganizationMutation) OldDescription(ctx context.Context) (v string, err error) {
	if !m.op.Is(OpUpdateOne) {
		return v, errors.New("OldDescription is only allowed on UpdateOne operations")
	}
	if m.id == nil || m.oldValue == nil {
		return v, errors.New("OldDescription requires an ID field in the mutation")
	}
	oldValue, err := m.oldValue(ctx)
	if err != nil {
		return v, fmt.Errorf("querying old value for OldDescription: %w", err)
	}
	return oldValue.Description, nil
}

// ClearDescription clears the value of the "description" field.
func (m *OrganizationMutation) ClearDescription() {
	m.description = nil
	m.clearedFields[organization.FieldDescription] = struct{}{}
}

// DescriptionCleared returns if the "description" field was cleared in this mutation.
func (m *OrganizationMutation) DescriptionCleared() bool {
	_, ok := m.clearedFields[organization.FieldDescription]
	return ok
}

// ResetDescription resets all changes to the "description" field.
func (m *OrganizationMutation) ResetDescription() {
	m.description = nil
	delete(m.clearedFields, organization.FieldDescription)
}

// Where appends a list predicates to the OrganizationMutation builder.
func (m *OrganizationMutation) Where(ps ...predicate.Organization) {
	m.predicates = append(m.predicates, ps...)
}

// WhereP appends storage-level predicates to the OrganizationMutation builder. Using this method,
// users can use type-assertion to append predicates that do not depend on any generated package.
func (m *OrganizationMutation) WhereP(ps ...func(*sql.Selector)) {
	p := make([]predicate.Organization, len(ps))
	for i := range ps {
		p[i] = ps[i]
	}
	m.Where(p...)
}

// Op returns the operation name.
func (m *OrganizationMutation) Op() Op {
	return m.op
}

// SetOp allows setting the mutation operation.
func (m *OrganizationMutation) SetOp(op Op) {
	m.op = op
}

// Type returns the node type of this mutation (Organization).
func (m *OrganizationMutation) Type() string {
	return m.typ
}

// Fields returns all fields that were changed during this mutation. Note that in
// order to get all numeric fields that were incremented/decremented, call
// AddedFields().
func (m *OrganizationMutation) Fields() []string {
	fields := make([]string, 0, 2)
	if m.name != nil {
		fields = append(fields, organization.FieldName)
	}
	if m.description != nil {
		fields = append(fields, organization.FieldDescription)
	}
	return fields
}

// Field returns the value of a field with the given name. The second boolean
// return value indicates that this field was not set, or was not defined in the
// schema.
func (m *OrganizationMutation) Field(name string) (ent.Value, bool) {
	switch name {
	case organization.FieldName:
		return m.Name()
	case organization.FieldDescription:
		return m.Description()
	}
	return nil, false
}

// OldField returns the old value of the field from the database. An error is
// returned if the mutation operation is not UpdateOne, or the query to the
// database failed.
func (m *OrganizationMutation) OldField(ctx context.Context, name string) (ent.Value, error) {
	switch name {
	case organization.FieldName:
		return m.OldName(ctx)
	case organization.FieldDescription:
		return m.OldDescription(ctx)
	}
	return nil, fmt.Errorf("unknown Organization field %s", name)
}

// SetField sets the value of a field with the given name. It returns an error if
// the field is not defined in the schema, or if the type mismatched the field
// type.
func (m *OrganizationMutation) SetField(name string, value ent.Value) error {
	switch name {
	case organization.FieldName:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("unexpected type %T for field %s", value, name)
		}
		m.SetName(v)
		return nil
	case organization.FieldDescription:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("unexpected type %T for field %s", value, name)
		}
		m.SetDescription(v)
		return nil
	}
	return fmt.Errorf("unknown Organization field %s", name)
}

// AddedFields returns all numeric fields that were incremented/decremented during
// this mutation.
func (m *OrganizationMutation) AddedFields() []string {
	return nil
}

// AddedField returns the numeric value that was incremented/decremented on a field
// with the given name. The second boolean return value indicates that this field
// was not set, or was not defined in the schema.
func (m *OrganizationMutation) AddedField(name string) (ent.Value, bool) {
	return nil, false
}

// AddField adds the value to the field with the given name. It returns an error if
// the field is not defined in the schema, or if the type mismatched the field
// type.
func (m *OrganizationMutation) AddField(name string, value ent.Value) error {
	switch name {
	}
	return fmt.Errorf("unknown Organization numeric field %s", name)
}

// ClearedFields returns all nullable fields that were cleared during this
// mutation.
func (m *OrganizationMutation) ClearedFields() []string {
	var fields []string
	if m.FieldCleared(organization.FieldDescription) {
		fields = append(fields, organization.FieldDescription)
	}
	return fields
}

// FieldCleared returns a boolean indicating if a field with the given name was
// cleared in this mutation.
func (m *OrganizationMutation) FieldCleared(name string) bool {
	_, ok := m.clearedFields[name]
	return ok
}

// ClearField clears the value of the field with the given name. It returns an
// error if the field is not defined in the schema.
func (m *OrganizationMutation) ClearField(name string) error {
	switch name {
	case organization.FieldDescription:
		m.ClearDescription()
		return nil
	}
	return fmt.Errorf("unknown Organization nullable field %s", name)
}

// ResetField resets all changes in the mutation for the field with the given name.
// It returns an error if the field is not defined in the schema.
func (m *OrganizationMutation) ResetField(name string) error {
	switch name {
	case organization.FieldName:
		m.ResetName()
		return nil
	case organization.FieldDescription:
		m.ResetDescription()
		return nil
	}
	return fmt.Errorf("unknown Organization field %s", name)
}

// AddedEdges returns all edge names that were set/added in this mutation.
func (m *OrganizationMutation) AddedEdges() []string {
	edges := make([]string, 0, 0)
	return edges
}

// AddedIDs returns all IDs (to other nodes) that were added for the given edge
// name in this mutation.
func (m *OrganizationMutation) AddedIDs(name string) []ent.Value {
	return nil
}

// RemovedEdges returns all edge names that were removed in this mutation.
func (m *OrganizationMutation) RemovedEdges() []string {
	edges := make([]string, 0, 0)
	return edges
}

// RemovedIDs returns all IDs (to other nodes) that were removed for the edge with
// the given name in this mutation.
func (m *OrganizationMutation) RemovedIDs(name string) []ent.Value {
	return nil
}

// ClearedEdges returns all edge names that were cleared in this mutation.
func (m *OrganizationMutation) ClearedEdges() []string {
	edges := make([]string, 0, 0)
	return edges
}

// EdgeCleared returns a boolean which indicates if the edge with the given name
// was cleared in this mutation.
func (m *OrganizationMutation) EdgeCleared(name string) bool {
	return false
}

// ClearEdge clears the value of the edge with the given name. It returns an error
// if that edge is not defined in the schema.
func (m *OrganizationMutation) ClearEdge(name string) error {
	return fmt.Errorf("unknown Organization unique edge %s", name)
}

// ResetEdge resets all changes to the edge with the given name in this mutation.
// It returns an error if the edge is not defined in the schema.
func (m *OrganizationMutation) ResetEdge(name string) error {
	return fmt.Errorf("unknown Organization edge %s", name)
}
