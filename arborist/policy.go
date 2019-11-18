package arborist

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Policy struct {
	Name          string   `json:"id"`
	Description   string   `json:"description"`
	ResourcePaths []string `json:"resource_paths"`
	RoleIDs       []string `json:"role_ids"`
}

type PolicyResource struct {
	Policy   int64 `db:"policy_id"`
	Resource int64 `db:"resource_id"`
}

// UnmarshalJSON defines the way that a `Policy` gets read when unmarshalling:
//
//     json.Unmarshal(bytes, &policy)
//
// We implement this method to add some additional processing and error
// checking, for example to reject inputs which are missing required fields.
func (policy *Policy) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}

	// id is optional here because PUT doesn't require it to be in the json;
	// handlePolicyOverwrite will populate id later, from the URL.
	// id is still validated later, in policy `validate` function.
	optionalFields := map[string]struct{}{
		"id":          struct{}{},
		"description": struct{}{},
	}
	err = validateJSON("policy", policy, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the PolicyJSON to.
	type loader Policy
	err = json.Unmarshal(data, (*loader)(policy))
	if err != nil {
		return err
	}

	return nil
}

// PolicyFromQuery defines the correct fields for loading policies from the
// database. Use this struct when querying from the `policy` table.
type PolicyFromQuery struct {
	ID            int64          `db:"id" json:"-"`
	Name          string         `db:"name" json:"id"`
	Description   *string        `db:"description" json:"description,omitempty"`
	ResourcePaths pq.StringArray `db:"resource_paths" json:"resource_paths"`
	RoleIDs       pq.StringArray `db:"role_ids" json:"role_ids"`
}

func (policyFromQuery *PolicyFromQuery) standardize() Policy {
	paths := make([]string, len(policyFromQuery.ResourcePaths))
	for i, queryPath := range policyFromQuery.ResourcePaths {
		paths[i] = formatDbPath(queryPath)
	}
	policy := Policy{
		Name:          policyFromQuery.Name,
		ResourcePaths: paths,
		RoleIDs:       policyFromQuery.RoleIDs,
	}
	if policyFromQuery.Description != nil {
		policy.Description = *policyFromQuery.Description
	}
	return policy
}

func fetchPolicyID(tx *sqlx.Tx, name string) (int, error) {
	var policyIDs []int

	err := tx.Select(&policyIDs, "SELECT ID FROM policy WHERE name = '"+name+"'")

	if err != nil {
		return 0, err
	}
	if len(policyIDs) > 0 {
		return policyIDs[0], nil
	}
	return 0, nil
}

func policyWithName(db *sqlx.DB, name string) (*PolicyFromQuery, error) {
	stmt := `
		SELECT
			policy.id,
			policy.name,
			policy.description,
			array_remove(array_agg(DISTINCT resource.path), NULL) AS resource_paths,
			array_remove(array_agg(DISTINCT role.name), NULL) AS role_ids
		FROM policy
		LEFT JOIN policy_resource ON policy.id = policy_resource.policy_id
		LEFT JOIN resource ON resource.id = policy_resource.resource_id
		LEFT JOIN policy_role on policy.id = policy_role.policy_id
		LEFT JOIN role on role.id = policy_role.role_id
		WHERE policy.name = $1
		GROUP BY policy.id
		LIMIT 1
	`
	policies := []PolicyFromQuery{}
	err := db.Select(&policies, stmt, name)
	if len(policies) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	policy := policies[0]
	return &policy, nil
}

func listPoliciesFromDb(db *sqlx.DB) ([]PolicyFromQuery, error) {
	stmt := `
		SELECT
			policy.id,
			policy.name,
			policy.description,
			array_remove(array_agg(DISTINCT resource.path), NULL) AS resource_paths,
			array_remove(array_agg(DISTINCT role.name), NULL) AS role_ids
		FROM policy
		LEFT JOIN policy_resource ON policy.id = policy_resource.policy_id
		LEFT JOIN resource ON resource.id = policy_resource.resource_id
		LEFT JOIN policy_role on policy.id = policy_role.policy_id
		LEFT JOIN role on role.id = policy_role.role_id
		GROUP BY policy.id
	`
	var policies []PolicyFromQuery
	err := db.Select(&policies, stmt)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

// resources looks up all the resources with paths in this policy. An error, if
// returned, resulted from the database operation.
func (policy *Policy) resources(tx *sqlx.Tx) ([]ResourceFromQuery, error) {
	resources := []ResourceFromQuery{}
	queryPaths := make([]string, len(policy.ResourcePaths))
	for i, path := range policy.ResourcePaths {
		queryPaths[i] = FormatPathForDb(path)
	}
	resourcesStmt := selectInStmt("resource", "ltree2text(path)", queryPaths)
	err := tx.Select(&resources, resourcesStmt)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

// roles looks up the roles which this policy references. An error, if
// returned, resulted from the database operation.
func (policy *Policy) roles(tx *sqlx.Tx) ([]RoleFromQuery, error) {
	roles := []RoleFromQuery{}
	rolesStmt := selectInStmt("role", "name", policy.RoleIDs)
	err := tx.Select(&roles, rolesStmt)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// validate does any basic validation on the policy which is possible without
// looking at the database. This includes that the policy must contain at least
// one resource and at least one role.
func (policy *Policy) validate() *ErrorResponse {
	if len(policy.Name) == 0 {
		return newErrorResponse("policy ID cannot be absent or empty", 400, nil)
	}
	// Resources and roles must be non-empty
	if len(policy.ResourcePaths) == 0 {
		return newErrorResponse("no resource paths specified", 400, nil)
	}
	if len(policy.RoleIDs) == 0 {
		return newErrorResponse("no role IDs specified", 400, nil)
	}
	return nil
}

// addResourcesAndRoles takes a policy and links it in the database
// to each of its resources and roles.
func (policy *Policy) addResourcesAndRoles(tx *sqlx.Tx, policyID int) *ErrorResponse {

	// `resources` is a list of looked-up resources which appear in the input policy
	resources, err := policy.resources(tx)
	if err != nil {
		msg := fmt.Sprintf("database call for resources failed: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}
	// make sure all resources for new policy exist in DB
	resourceSet := make(map[string]struct{})
	for _, resource := range resources {
		path := formatDbPath(resource.Path)
		resourceSet[path] = struct{}{}
	}
	missingResources := []string{}
	for _, path := range policy.ResourcePaths {
		if _, exists := resourceSet[path]; !exists {
			missingResources = append(missingResources, path)
		}
	}
	if len(missingResources) > 0 {
		missingString := strings.Join(missingResources, ", ")
		msg := fmt.Sprintf("failed to create policy: resources do not exist: %s", missingString)
		return newErrorResponse(msg, 400, nil)
	}
	// try to insert relationships from this policy to all resources
	stmt := multiInsertStmt("policy_resource(policy_id, resource_id)", len(resources))
	policyResourceRows := []interface{}{}
	for _, resource := range resources {
		policyResourceRows = append(policyResourceRows, policyID)
		policyResourceRows = append(policyResourceRows, resource.ID)
	}
	_, err = tx.Exec(stmt, policyResourceRows...)
	if err != nil {
		msg := fmt.Sprintf("failed to insert policy while linking resources: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	roles, err := policy.roles(tx)
	if err != nil {
		msg := fmt.Sprintf("database call for roles failed: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}
	// make sure all resources for new policy exist in DB
	roleSet := make(map[string]struct{})
	for _, role := range roles {
		roleSet[role.Name] = struct{}{}
	}
	missingRoles := []string{}
	for _, role := range policy.RoleIDs {
		if _, exists := roleSet[role]; !exists {
			missingRoles = append(missingRoles, role)
		}
	}
	if len(missingRoles) > 0 {
		missingString := strings.Join(missingRoles, ", ")
		msg := fmt.Sprintf("failed to create policy: roles do not exist: %s", missingString)
		return newErrorResponse(msg, 400, nil)
	}
	// try to insert relationships from this policy to all roles
	stmt = multiInsertStmt("policy_role(policy_id, role_id)", len(roles))
	policyRoleRows := []interface{}{}
	for _, role := range roles {
		policyRoleRows = append(policyRoleRows, policyID)
		policyRoleRows = append(policyRoleRows, role.ID)
	}
	_, err = tx.Exec(stmt, policyRoleRows...)
	if err != nil {
		msg := fmt.Sprintf("failed to insert policy while linking roles: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	return nil
}

// createInDb writes out the policy to the database.
func (policy *Policy) createInDb(tx *sqlx.Tx) *ErrorResponse {
	errResponse := policy.validate()
	if errResponse != nil {
		return errResponse
	}

	var policyID int
	// TODO: make sure description works as expected
	stmt := "INSERT INTO policy(name, description) VALUES ($1, $2) RETURNING id"
	row := tx.QueryRowx(stmt, policy.Name, policy.Description)
	err := row.Scan(&policyID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		// this should only fail because the policy was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert policy: policy with this ID already exists: %s", policy.Name)
		return newErrorResponse(msg, 409, &err)
	}

	errResponse = policy.addResourcesAndRoles(tx, policyID)
	if errResponse != nil {
		return errResponse
	}

	return nil
}

func (policy *Policy) deleteInDb(tx *sqlx.Tx) *ErrorResponse {
	stmt := "DELETE FROM policy WHERE name = $1"
	_, err := tx.Exec(stmt, policy.Name)
	if err != nil {
		// TODO: verify correct error
		// doesn't exist, this is fine
		return nil
	}
	return nil
}

func (policy *Policy) updateInDb(tx *sqlx.Tx) *ErrorResponse {
	// We do not allow updates to policy name (or id).

	errResponse := policy.validate()
	if errResponse != nil {
		return errResponse
	}

	var policyID int
	stmt := "UPDATE policy SET description = $1 WHERE name = $2 RETURNING id"
	row := tx.QueryRowx(stmt, policy.Description, policy.Name)
	err := row.Scan(&policyID)
	switch {
	case err == sql.ErrNoRows:
		msg := fmt.Sprintf("failed to update policy: no policy found with id: %s", policy.Name)
		return newErrorResponse(msg, 404, &err)
	case err != nil:
		msg := fmt.Sprintf("failed to update policy: update description failed: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// First delete resources and roles that were previously attached to policy
	stmt = "DELETE FROM policy_resource WHERE policy_id = $1"
	_, err = tx.Exec(stmt, policyID)
	if err != nil {
		msg := fmt.Sprintf("database deletion from policy_resource failed: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}
	stmt = "DELETE FROM policy_role WHERE policy_id = $1"
	_, err = tx.Exec(stmt, policyID)
	if err != nil {
		msg := fmt.Sprintf("database deletion from policy_role failed: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// Now add the new resources and roles
	errResponse = policy.addResourcesAndRoles(tx, policyID)
	if errResponse != nil {
		return errResponse
	}

	return nil
}
