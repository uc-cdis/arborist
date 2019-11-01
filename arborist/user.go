package arborist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type PolicyBinding struct {
	Policy    string  `json:"policy"`
	Role      string  `json:"role"`
	Resource  string  `json:"resource"`
	ExpiresAt *string `json:"expires_at"`
}

type GroupBinding struct {
	Name     string          `json:"name"`
	Policies []PolicyBinding `json:"policies"`
}

func (policyBinding *PolicyBinding) standardize() PolicyBinding {
	policy := PolicyBinding{
		Policy:    policyBinding.Policy,
		Role:      policyBinding.Role,
		Resource:  UnderscoreDecode(policyBinding.Resource),
		ExpiresAt: policyBinding.ExpiresAt,
	}
	return policy
}

type FenceUser struct {
	Name          string `json:"name"`
	Email         string `json:"email,omitempty"`
	PreferredName string `json:"preferred_username"`
	Active        bool   `json:"active"`
}

type FenceUsers struct {
	Users      []FenceUser `json:"users"`
	Pagination Pagination  `json:"pagination"`
}

type User struct {
	Name               string          `json:"name"`
	Email              string          `json:"email,omitempty"`
	PreferredName      string          `json:"preferred_username"`
	Active             bool            `json:"active"`
	Groups             []string        `json:"groups"`
	GroupsWithPolicies []GroupBinding  `json:"groups_with_policies"`
	Policies           []PolicyBinding `json:"policies"`
}

type Users struct {
	Users    []User          `json:"users"`
	Policies []PolicyBinding `json:"policies"`
	Groups   []string        `json:"groups"`
}

func (user *User) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"email":                struct{}{},
		"active":               struct{}{},
		"groups":               struct{}{},
		"policies":             struct{}{},
		"groups_with_policies": struct{}{},
	}
	err = validateJSON("user", user, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the Role to. Since this is just type conversion there's no
	// runtime cost.
	type loader User
	err = json.Unmarshal(data, (*loader)(user))
	if err != nil {
		return err
	}

	return nil
}

type UserFromQuery struct {
	ID                 int            `db:"id"`
	Name               string         `db:"name"`
	Email              *string        `db:"email"`
	Groups             pq.StringArray `db:"groups"`
	GroupsWithPolicies []byte         `db:"groups_with_policies"`
	Policies           []byte         `db:"policies"`
}

func (fenceUser *FenceUser) standardize() User {
	user := User{
		Name:               fenceUser.Name,
		PreferredName:      fenceUser.PreferredName,
		Email:              fenceUser.Email,
		Active:             fenceUser.Active,
		GroupsWithPolicies: []GroupBinding{},
		Policies:           []PolicyBinding{},
		Groups:             []string{},
	}
	return user
}

func (userFromQuery *UserFromQuery) standardize(fenceUser *FenceUser) User {
	if len(userFromQuery.Policies) == 0 {
		userFromQuery.Policies = []byte("[]")
	}
	if len(userFromQuery.GroupsWithPolicies) == 0 {
		userFromQuery.GroupsWithPolicies = []byte("[]")
	}
	policies := []PolicyBinding{}
	resultPolicies := []PolicyBinding{}
	err := json.Unmarshal(userFromQuery.Policies, &policies)
	for _, policyBinding := range policies {
		policy := policyBinding.standardize()
		resultPolicies = append(resultPolicies, policy)
	}
	if err != nil {
		// debug
		fmt.Printf("ERROR: UserFromQuery loader is broken: %s\n", err.Error())
	}

	groups := []GroupBinding{}
	groupPolicies := []PolicyBinding{}
	resultGroups := []GroupBinding{}
	err = json.Unmarshal(userFromQuery.GroupsWithPolicies, &groups)
	if err != nil {
		fmt.Printf("ERROR: UserFromQuery loader is broken: %s\n", err.Error())
	}
	for _, group := range groups {
		groupPolicies = []PolicyBinding{}
		newGroup := GroupBinding{}
		for _, policyBinding := range group.Policies {
			policy := policyBinding.standardize()
			groupPolicies = append(groupPolicies, policy)
		}
		newGroup.Name = group.Name
		newGroup.Policies = groupPolicies
		resultGroups = append(resultGroups, newGroup)
	}

	user := User{
		Name:               userFromQuery.Name,
		Groups:             userFromQuery.Groups,
		GroupsWithPolicies: resultGroups,
		Policies:           resultPolicies,
	}
	if fenceUser != nil {
		user.PreferredName = fenceUser.PreferredName
		user.Email = fenceUser.Email
		user.Active = fenceUser.Active
	}
	return user
}

func userWithName(db *sqlx.DB, name string) (*UserFromQuery, error) {
	stmt := `
		SELECT
			usr.id,
			usr.name,
			usr.email,
			array_remove(array_agg(DISTINCT grp.name), NULL) AS groups,
			(
				SELECT json_agg(json_build_object('policy', policy.name, 'expires_at', usr_policy.expires_at))
				FROM usr_policy
				INNER JOIN policy ON policy.id = usr_policy.policy_id
				WHERE usr_policy.usr_id = usr.id
			) AS policies
		FROM usr
		LEFT JOIN usr_grp ON usr_grp.usr_id = usr.id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
		WHERE usr.name = $1
		GROUP BY usr.id
	`
	users := []UserFromQuery{}
	err := db.Select(&users, stmt, name)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	user := users[0]
	user.Groups = append(user.Groups, LoggedInGroup)
	return &user, nil
}

func createOrUpdateUser(server *Server, w http.ResponseWriter, r *http.Request, user *User, create bool) {
	db := server.db
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		response := newErrorResponse(msg, 500, &err)
		_ = response.write(w, r)
		return
	}
	// fetch fence user
	fenceUser, statusCode, err := fetchFenceUser(server.fence, r, user)
	if err != nil {
		msg := fmt.Sprintf("could not fetch user from fence: %s", err.Error())
		server.logger.Info("tried to update user but input was invalid: %s", msg)
		response := newErrorResponse(msg, statusCode, nil)
		_ = response.write(w, r)
		return
	} else if fenceUser == nil {
		if !create {
			msg := fmt.Sprintf("could not fetch user from fence")
			server.logger.Info("tried to update user but input was invalid: %s", msg)
			response := newErrorResponse(msg, 404, nil)
			_ = response.write(w, r)
			return
		}
	}
	// fetch arborist user
	existUserID, err := fetchArboristUserID(tx, user.Name)
	if err != nil {
		msg := fmt.Sprintf("could not fetch user from arborist: %s", err.Error())
		server.logger.Info("tried to update user but input was invalid: %s", msg)
		response := newErrorResponse(msg, 500, nil)
		_ = response.write(w, r)
		return
	}
	authzProvider := getAuthZProvider(r)
	if existUserID != 0 {
		errResponse := user.updateInDb(tx, user.Name, authzProvider)
		if errResponse != nil {
			errResponse.log.write(server.logger)
			_ = errResponse.write(w, r)
			_ = tx.Rollback()
			return
		}
	} else {
		var userID int
		stmt := `
			INSERT INTO usr(name)
			VALUES ($1)
			RETURNING id
		`
		row := tx.QueryRowx(stmt, user.Name)
		err = row.Scan(&userID)
		if err != nil {
			// should add more checking here to guarantee the correct error
			_ = tx.Rollback()
			// this should only fail because the user was not unique. return error
			// accordingly
			msg := fmt.Sprintf("failed to insert user: user with this ID already exists: %s", user.Name)
			response := newErrorResponse(msg, 409, nil)
			_ = response.write(w, r)
			return
		}

		errResponse := multiCreateGroupInDb(tx, user.Groups, userID)
		if errResponse != nil {
			errResponse.log.write(server.logger)
			_ = errResponse.write(w, r)
			_ = tx.Rollback()
			return
		}
		errResponse = multiCreatePolicyInDb(tx, user.Policies, userID)
		if errResponse != nil {
			errResponse.log.write(server.logger)
			_ = errResponse.write(w, r)
			_ = tx.Rollback()
			return
		}
	}
	if create && fenceUser == nil {
		_, statusCode, err = createFenceUser(server.fence, r, user)
	} else {
		_, statusCode, err = updateFenceUser(server.fence, r, user)
	}
	if err != nil {
		msg := "could not update user to fence: " + err.Error()
		server.logger.Info("tried to update user but input was invalid: %s", msg)
		response := newErrorResponse(msg, statusCode, nil)
		_ = response.write(w, r)
		_ = tx.Rollback()
		return
	}
	err = tx.Commit()
	if err != nil {
		msg := "couldn't commit database transaction: " + err.Error()
		server.logger.Info("tried to update user but input was invalid: %s", msg)
		response := newErrorResponse(msg, 500, nil)
		_ = response.write(w, r)
		_ = tx.Rollback()
		return
	}
}

func fetchFenceUser(fence *FenceServer, r *http.Request, user *User) (*FenceUser, int, error) {
	resp, err := fence.request(r, "/admin/user/"+user.Name, "GET", nil)
	if err != nil {
		return nil, 500, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, resp.StatusCode, nil
	}
	if resp.StatusCode != 200 {
		return nil, resp.StatusCode, errors.New(resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 500, err
	}
	fenceUser := FenceUser{}
	err = json.Unmarshal(body, &fenceUser)
	if err != nil {
		return nil, 500, err
	}
	return &fenceUser, 200, nil
}

func fetchArboristUserID(tx *sqlx.Tx, username string) (int, error) {
	var userIDs []int

	err := tx.Select(&userIDs, "SELECT ID FROM usr WHERE name = '"+username+"'")
	if err != nil {
		return 0, err
	}
	if len(userIDs) > 0 {
		return userIDs[0], nil
	}
	return 0, nil
}

func createFenceUser(fence *FenceServer, r *http.Request, user *User) (*FenceUser, int, error) {
	values := map[string]interface{}{}
	values["name"] = user.Name
	values["display_name"] = user.PreferredName
	values["email"] = user.Email
	resp, err := fence.request(r, "/admin/user", "POST", values)
	if err != nil {
		return nil, 500, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err := errors.New(resp.Status)
		return nil, resp.StatusCode, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 500, err
	}
	fenceUser := FenceUser{}
	err = json.Unmarshal(body, &fenceUser)
	if err != nil {
		return nil, 500, err
	}
	return &fenceUser, 200, nil
}

func updateFenceUser(fence *FenceServer, r *http.Request, user *User) (*FenceUser, int, error) {
	values := map[string]interface{}{}
	values["active"] = user.Active
	values["display_name"] = user.PreferredName
	values["email"] = user.Email
	resp, err := fence.request(r, "/admin/user/"+user.Name, "PUT", values)
	if err != nil {
		return nil, 500, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err := errors.New(resp.Status)
		return nil, resp.StatusCode, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 500, err
	}
	fenceUser := FenceUser{}
	err = json.Unmarshal(body, &fenceUser)
	if err != nil {
		return nil, 500, err
	}
	return &fenceUser, 200, nil
}

func fetchFenceUsers(server *Server, w http.ResponseWriter, r *http.Request) (*FenceUsers, int, error) {
	vars := r.URL.Query()
	var page string
	var pageSize string
	var keyword string
	page = vars.Get("page")
	pageSize = vars.Get("page_size")
	keyword = vars.Get("keyword")
	var fenceResp *http.Response
	params := make([]string, 0)
	if keyword != "" {
		params = append(params, "keyword="+keyword)
	}
	if len(vars["groups[]"]) != 0 || len(vars["resources[]"]) != 0 || len(vars["roles[]"]) != 0 {
		path := "/admin/user"
		if len(params) > 0 {
			path = path + "?" + strings.Join(params, "&")
		}
		resp, err := server.fence.request(r, path, "GET", nil)
		if err != nil {
			return nil, 500, err
		}
		fenceResp = resp
	} else {
		params = append(params, "page="+page)
		params = append(params, "page_size="+pageSize)
		path := "/admin/paginated_users"
		path = path + "?" + strings.Join(params, "&")
		resp, err := server.fence.request(r, path, "GET", nil)
		if err != nil {
			return nil, 500, err
		}
		fenceResp = resp
	}
	defer fenceResp.Body.Close()
	if fenceResp.StatusCode != 200 {
		err := errors.New(fenceResp.Status)
		return nil, fenceResp.StatusCode, err
	}
	body, err := ioutil.ReadAll(fenceResp.Body)
	if err != nil {
		return nil, 500, err
	}
	fenceUsers := FenceUsers{}
	err = json.Unmarshal(body, &fenceUsers)
	if err != nil {
		return nil, 500, err
	}
	return &fenceUsers, 200, nil
}

func listUsersFromDb(db *sqlx.DB, r *http.Request, userNames []string, pag *Pagination, inUserNames bool) ([]UserFromQuery, *Pagination, error) {
	stmt := `
		SELECT
			usr.id,
			usr.name,
			usr.email,
			(
				SELECT json_agg(json_build_object('name', grp.name, 'policies', (
					SELECT json_agg(json_build_object('policy',policy.name, 'role', role.name ,'resource', resource.name, 'resource_path', resource.path)) 
					FROM grp_policy 
					INNER JOIN policy ON policy.id = grp_policy.policy_id 
					INNER JOIN policy_role ON policy_role.policy_id = policy.id 
					INNER JOIN role ON role.id = policy_role.role_id 
					LEFT JOIN policy_resource ON policy_resource.policy_id = policy.id 
					LEFT JOIN resource ON resource.id = policy_resource.resource_id
					WHERE grp_policy.grp_id = grp.id)))  
				FROM usr_grp 
				LEFT JOIN grp ON usr_grp.grp_id = grp.id 
				WHERE usr_grp.usr_id = usr.id
			) AS groups_with_policies,
			array_remove(array_agg(DISTINCT grp.name), NULL) AS groups,
			(
				SELECT json_agg(json_build_object('policy', policy.name, 'expires_at', usr_policy.expires_at, 'role', role.name, 'resource', resource.name, 'resource_path', resource.path)) 
				FROM usr_policy
				INNER JOIN policy ON policy.id = usr_policy.policy_id
				INNER JOIN policy_role ON policy_role.policy_id = policy.id
				INNER JOIN role ON role.id = policy_role.role_id
				LEFT JOIN policy_resource ON policy_resource.policy_id = policy.id
				LEFT JOIN resource ON resource.id = policy_resource.resource_id
				WHERE usr_policy.usr_id = usr.id
			) AS policies
		FROM usr
		LEFT JOIN usr_grp ON usr.id = usr_grp.usr_id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
	`
	vars := r.URL.Query()
	conditions := make([]string, 0)
	rolesConditions := make([]string, 0)
	resourceConditions := make([]string, 0)
	groupConditions := make([]string, 0)
	if len(vars["groups[]"]) != 0 {
		for _, v := range vars["groups[]"] {
			groupConditions = append(groupConditions, "'"+v+"'")
		}
		if len(groupConditions) != 0 {
			conditions = append(conditions, "ARRAY["+strings.Join(groupConditions, ",")+"] && array_remove(array_agg(DISTINCT grp.name), NULL)")
		}
	}
	if len(vars["resources[]"]) != 0 {
		for _, v := range vars["resources[]"] {
			resourceConditions = append(resourceConditions, "'"+v+"'")
		}
	}
	if len(vars["roles[]"]) != 0 {
		for _, v := range vars["roles[]"] {
			rolesConditions = append(rolesConditions, "'"+v+"'")
		}
	}
	if len(vars["resources[]"]) != 0 && len(vars["roles[]"]) != 0 {
		conditions = append(conditions, "ARRAY(SELECT (role.id, resource.id) FROM role, resource WHERE role.name in ("+strings.Join(rolesConditions, ", ")+") AND resource.tag in ("+strings.Join(resourceConditions, ", ")+")) && array_agg(DISTINCT(role.id, resource.id))")
	} else {
		if len(resourceConditions) != 0 {
			conditions = append(conditions, "ARRAY["+strings.Join(resourceConditions, ",")+"] && array_agg(resource.tag)")
		}
		if len(rolesConditions) != 0 {
			conditions = append(conditions, "ARRAY["+strings.Join(rolesConditions, ", ")+"] && array_agg(DISTINCT role.name)")
		}
	}
	if len(resourceConditions) != 0 || len(rolesConditions) != 0 {
		stmt = stmt + `
		LEFT JOIN usr_policy ON usr_policy.usr_id = usr.id LEFT JOIN policy ON policy.id = usr_policy.policy_id`
		if len(rolesConditions) != 0 {
			stmt = stmt + `
			LEFT JOIN policy_role ON policy_role.policy_id = policy.id LEFT JOIN role ON role.id = policy_role.role_id
			`
		}
		if len(resourceConditions) != 0 {
			stmt = stmt + `
			LEFT JOIN policy_resource ON policy_resource.policy_id = policy.id LEFT JOIN resource ON resource.id = policy_resource.resource_id
			`
		}
	}
	if inUserNames {
		stmt = stmt + `
			WHERE usr.name in ('` + strings.Join(userNames, "', '") + `')
		`
	}
	stmt = stmt + `
		GROUP BY usr.id
	`
	if len(conditions) != 0 {
		stmt = stmt + "HAVING " + strings.Join(conditions, " AND ")
	}
	users := []UserFromQuery{}
	if pag.Page == 0 {
		pagination, err := SelectWithPagination(db, &users, stmt, r)
		if err != nil {
			return nil, nil, err
		}
		return users, pagination, nil
	} else {
		err := db.Select(&users, stmt)
		if err != nil {
			return nil, nil, err
		}
		return users, pag, nil
	}
}

func (user *User) createInDb(db *sqlx.DB) *ErrorResponse {
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// First, insert permissions if they don't exist yet. If they don't exist
	// then use the contents of this user to create them; if they exist already
	// then IGNORE the contents, and use what's in the database. In postgres we
	// can use `ON CONFLICT DO NOTHING` for this.

	var userID int
	stmt := `
		INSERT INTO usr(name, email)
		VALUES ($1, $2)
		RETURNING id
	`
	row := tx.QueryRowx(stmt, user.Name, user.Email)
	err = row.Scan(&userID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		_ = tx.Rollback()
		// this should only fail because the user was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert user: user with this ID already exists: %s", user.Name)
		return newErrorResponse(msg, 409, &err)
	}

	err = tx.Commit()
	if err != nil {
		_ = tx.Rollback()
		msg := fmt.Sprintf("couldn't commit database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	return nil
}

func (user *User) updateInDb(tx *sqlx.Tx, nameInDb string, authzProvider sql.NullString) *ErrorResponse {
	errResponse := revokeUserPolicyAll(tx, user.Name, authzProvider)
	if errResponse != nil {
		msg := "Update user fail - revoke user policy: " + user.Name
		return newErrorResponse(msg, 500, nil)
	}

	errResponse = revokeUserGroupAll(tx, user.Name, authzProvider)
	if errResponse != nil {
		msg := "Update user fail - revoke user group: " + user.Name
		return newErrorResponse(msg, 500, nil)
	}

	existUserID, err := fetchArboristUserID(tx, user.Name)

	if err != nil {
		msg := "user query failed"
		return newErrorResponse(msg, 500, &err)
	}

	if len(user.Groups) != 0 {
		errResponse = multiCreateGroupInDb(tx, user.Groups, existUserID)
		if errResponse != nil {
			return errResponse
		}
	}
	if len(user.Policies) != 0 {
		errResponse = multiCreatePolicyInDb(tx, user.Policies, existUserID)
		if errResponse != nil {
			return errResponse
		}
	}

	return nil
}

func multiCreatePolicyInDb(tx *sqlx.Tx, Policies []PolicyBinding, userID int) *ErrorResponse {
	var err error = nil
	newPolicies := make([] struct {
		policyBinding PolicyBinding
		policyID      int64
	}, 0)
	if len(Policies) <= 0 {
		return nil
	}
	userPolicyStmt := multiInsertStmt("usr_policy(usr_id,policy_id)", len(Policies))
	userPolicyRows := []interface{}{}
	newPolicyWithoutResourceQuantity := 0
	for _, policyBinding := range Policies {
		var policyID int64
		policyInDb, err := fetchPolicyID(tx, policyBinding.Policy)
		if err != nil {
			msg := "policy query failed: " + err.Error()
			return newErrorResponse(msg, 500, &err)
		}
		if policyInDb == 0 {
			// policy does not exist, insert the policy, get ID.
			stmt := "INSERT INTO policy(name, description) VALUES ($1, $2) RETURNING id"
			row := tx.QueryRowx(stmt, policyBinding.Policy, "")
			err := row.Scan(&policyID)

			if err != nil {
				msg := fmt.Sprintf("failed to insert policy: policy with this ID already exists: %s",
					policyBinding.Policy)
				return newErrorResponse(msg, 409, &err)
			}
			newPolicies = append(newPolicies, struct {
				policyBinding PolicyBinding
				policyID      int64
			}{policyBinding: policyBinding, policyID: policyID})
			// When the policy is new and the policy only binds role
			if policyBinding.Resource == "" {
				newPolicyWithoutResourceQuantity = newPolicyWithoutResourceQuantity + 1
			}
		} else {
			policyID = int64(policyInDb)
		}
		userPolicyRows = append(userPolicyRows, userID)
		userPolicyRows = append(userPolicyRows, policyID)
	}

	policyRoleStmt := multiInsertStmt("policy_role(policy_id, role_id)", len(newPolicies))
	policyResourceStmt := multiInsertStmt("policy_resource(policy_id, resource_id)", len(newPolicies)-newPolicyWithoutResourceQuantity)
	policyRoleRows := []interface{}{}
	policyResourceRows := []interface{}{}

	if len(newPolicies) != 0 {
		// new policy requires binding of role and resource
		for i, policy := range newPolicies {
			// create policy with resource and role
			policyRoleStmt = strings.Replace(policyRoleStmt, "$"+strconv.Itoa(i*2+2),
				"(SELECT id FROM role WHERE name = $"+strconv.Itoa(i*2+2)+")", 1)
			if i < (len(newPolicies) - newPolicyWithoutResourceQuantity) {
				policyResourceStmt = strings.Replace(policyResourceStmt, "$"+strconv.Itoa(i*2+2),
					"(SELECT id FROM resource WHERE name = $"+strconv.Itoa(i*2+2)+")", 1)
			}
			policyRoleRows = append(policyRoleRows, policy.policyID)
			if policy.policyBinding.Resource != "" {
				policyResourceRows = append(policyResourceRows, policy.policyID)
				policyResourceRows = append(policyResourceRows, UnderscoreEncode(policy.policyBinding.Resource))
			}
			policyRoleRows = append(policyRoleRows, policy.policyBinding.Role)
			// Resource name needs to encode
		}
		_, err = tx.Exec(policyRoleStmt, policyRoleRows...)
		if err != nil {
			msg := fmt.Sprintf("failed to bind Role with policy while adding users: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}

		if len(newPolicies)-newPolicyWithoutResourceQuantity > 0 {
			_, err = tx.Exec(policyResourceStmt, policyResourceRows...)
			if err != nil {
				msg := fmt.Sprintf("failed to bind Resource with policy while adding users: %s", err.Error())
				return newErrorResponse(msg, 500, &err)
			}
		}
	}

	_, err = tx.Exec(userPolicyStmt, userPolicyRows...)
	if err != nil {
		msg := fmt.Sprintf("failed to bind user with policy while adding users: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func multiCreateGroupInDb(tx *sqlx.Tx, Groups []string, userID int) *ErrorResponse {
	if len(Groups) <= 0 {
		return nil
	}
	stmt := multiInsertStmt("usr_grp(usr_id, grp_id)", len(Groups))
	userGroupRows := []interface{}{}
	for i, groupName := range Groups {
		if groupName == AnonymousGroup || groupName == LoggedInGroup {
			return newErrorResponse("can't add users to built-in groups", 400, nil)
		}
		stmt = strings.Replace(stmt, "$"+strconv.Itoa(i*2+2),
			"(SELECT id FROM grp WHERE name = $"+strconv.Itoa(i*2+2)+")", 1)
		userGroupRows = append(userGroupRows, userID)
		userGroupRows = append(userGroupRows, groupName)
	}
	_, err := tx.Exec(stmt, userGroupRows...)
	if err != nil {
		msg := fmt.Sprintf("failed to bind group while adding users: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func (users *Users) multiCreateInDb(server *Server, w http.ResponseWriter, r *http.Request, ) *ErrorResponse {
	db := server.db
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// First, insert policy if they don't exist yet. if they exist already
	// then ONLY need to bind the policy to the user.

	for _, user := range users.Users {
		// fetch fence user
		fenceUser, statusCode, err := fetchFenceUser(server.fence, r, &user)
		if err != nil {
			_ = tx.Rollback()
			msg := fmt.Sprintf("could not fetch user from fence: %s", err.Error())
			server.logger.Info("on fetch user from Fence: %s", msg)
			//response := newErrorResponse(msg, 500, nil)
			//_ = response.write(w, r)
			return newErrorResponse(msg, statusCode, &err)
		}
		if fenceUser != nil {
			_ = tx.Rollback()
			msg := fmt.Sprintf("user with this name already exists in Fence")
			return newErrorResponse(msg, 409, &err)
		}

		existUserID, err := fetchArboristUserID(tx, user.Name)
		if existUserID != 0 {
			_ = tx.Rollback()
			msg := fmt.Sprintf("user with this name already exists in Arborist")
			return newErrorResponse(msg, 409, &err)
		}

		_, statusCode, err = createFenceUser(server.fence, r, &user)
		if err != nil {
			msg := "failed to insert user: " + err.Error()
			server.logger.Info("tried to create user to fence but failed: %s", msg)
			_ = tx.Rollback()
			return newErrorResponse(msg, statusCode, nil)
		}

		var userID int
		stmt := `
			INSERT INTO usr(name, email)
			VALUES ($1, $2)
			RETURNING id
		`
		row := tx.QueryRowx(stmt, user.Name, user.Email)
		err = row.Scan(&userID)
		if err != nil {
			_ = tx.Rollback()
			// this should only fail because the user was not unique. return error
			// accordingly
			msg := fmt.Sprintf("failed to insert user: user with this ID already exists: %s", user.Name)
			return newErrorResponse(msg, 409, &err)
		}

		errResponse := multiCreateGroupInDb(tx, users.Groups, userID)
		if errResponse != nil {
			_ = tx.Rollback()
			msg := fmt.Sprintf("Create user fail - create groups: %s", user.Name)
			return newErrorResponse(msg, 500, &err)
		}
		errResponse = multiCreatePolicyInDb(tx, users.Policies, userID)
		if errResponse != nil {
			_ = tx.Rollback()
			msg := fmt.Sprintf("Create user fail - create policies: %s", user.Name)
			return newErrorResponse(msg, 500, &err)
		}
	}

	err = tx.Commit()
	if err != nil {
		_ = tx.Rollback()
		msg := fmt.Sprintf("couldn't commit database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	return nil
}

func (user *User) deleteInDb(db *sqlx.DB) *ErrorResponse {
	stmt := "DELETE FROM usr WHERE name = $1"
	_, err := db.Exec(stmt, user.Name)
	if err != nil {
		// TODO: verify correct error
		// user does not exist; that's fine
		return nil
	}
	return nil
}

func grantUserPolicy(db *sqlx.DB, username string, policyName string, expiresAt *time.Time, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		INSERT INTO usr_policy(usr_id, policy_id, expires_at, authz_provider)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM policy WHERE name = $2), $3, $4)
		ON CONFLICT (usr_id, policy_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`
	_, err := db.Exec(stmt, username, policyName, expiresAt, authzProvider)
	if err != nil {
		user, err := userWithName(db, username)
		if user == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to user: user does not exist: %s",
				username,
			)
			return newErrorResponse(msg, 404, nil)
		}
		if err != nil {
			msg := "user query failed"
			return newErrorResponse(msg, 500, &err)
		}
		policy, err := policyWithName(db, policyName)
		if policy == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to user: policy does not exist: %s",
				policyName,
			)
			return newErrorResponse(msg, 400, nil)
		}
		if err != nil {
			msg := "policy query failed"
			return newErrorResponse(msg, 500, &err)
		}
		// at this point, we assume the user already has this policy. this is fine.
	}
	return nil
}

func revokeUserPolicy(db *sqlx.DB, username string, policyName string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
		AND policy_id = (SELECT id FROM policy WHERE name = $2)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $3"
		_, err = db.Exec(stmt, username, policyName, authzProvider)
	} else {
		_, err = db.Exec(stmt, username, policyName)
	}
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func revokeUserPolicyAll(tx *sqlx.Tx, username string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $2"
		_, err = tx.Exec(stmt, username, authzProvider)
	} else {
		_, err = tx.Exec(stmt, username)
	}
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func revokeUserGroupAll(tx *sqlx.Tx, username string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM usr_grp
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $2"
		_, err = tx.Exec(stmt, username, authzProvider)
	} else {
		_, err = tx.Exec(stmt, username)
	}
	if err != nil {
		msg := "revoke group query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func addUserToGroup(db *sqlx.DB, username string, groupName string, expiresAt *time.Time, authzProvider sql.NullString) *ErrorResponse {
	if groupName == AnonymousGroup || groupName == LoggedInGroup {
		return newErrorResponse("can't add users to built-in groups", 400, nil)
	}
	if username == "" {
		return newErrorResponse("missing `username` argument", 400, nil)
	}
	stmt := `
		INSERT INTO usr_grp(usr_id, grp_id, expires_at, authz_provider)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM grp WHERE name = $2), $3, $4)
		ON CONFLICT (usr_id, grp_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`
	_, err := db.Exec(stmt, username, groupName, expiresAt, authzProvider)
	if err != nil {
		user, err := userWithName(db, username)
		if user == nil {
			msg := fmt.Sprintf(
				"failed to add user to group: user does not exist: `%s`",
				username,
			)
			return newErrorResponse(msg, 400, nil)
		}
		if err != nil {
			msg := "user query failed"
			return newErrorResponse(msg, 500, &err)
		}
		group, err := groupWithName(db, groupName)
		if group == nil {
			msg := fmt.Sprintf(
				"failed to add user to group: group does not exist: %s",
				groupName,
			)
			return newErrorResponse(msg, 404, nil)
		}
		if err != nil {
			msg := "group query failed"
			return newErrorResponse(msg, 500, &err)
		}
		// at this point, we assume the user is already in the group. this is fine
	}
	return nil
}

func removeUserFromGroup(db *sqlx.DB, username string, groupName string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM usr_grp
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
		AND grp_id = (SELECT id FROM grp WHERE name = $2)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $3"
		_, err = db.Exec(stmt, username, groupName, authzProvider)
	} else {
		_, err = db.Exec(stmt, username, groupName)
	}
	if err != nil {
		msg := "remove user from group query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}
