package arborist

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// ResoruceJSON defines a representation of a Resource that can be serialized
// directly into JSON using `json.Marshal`.
//
// A note on the fields here: either the resource must have been created
// through the subresources field of a parent resource, in which case the path
// is formed from the parent path joined with this resource's name, or with an
// explicit full path here.
type Resource struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Description  string   `json:"description"`
	Subresources []string `json:"subresources"`
}

// NOTE: the resource unmarshalling, because the resources can be specified
// with either the name + endpoint path, or the full path in the JSON input, is
// not able to validate all cases precisely. The unmarshalling will pass as
// long as either the name or the path is provided, which may require
// additional validation where this is called.
func (resource *Resource) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}

	optionalFieldsPath := map[string]struct{}{
		"name":         struct{}{},
		"description":  struct{}{},
		"subresources": struct{}{},
	}
	errPath := validateJSON("resource", resource, fields, optionalFieldsPath)
	optionalFieldsName := map[string]struct{}{
		"path":         struct{}{},
		"description":  struct{}{},
		"subresources": struct{}{},
	}
	errName := validateJSON("resource", resource, fields, optionalFieldsName)
	if errPath != nil && errName != nil {
		return errPath
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the Resource to.
	type loader Resource
	err = json.Unmarshal(data, (*loader)(resource))
	if err != nil {
		return err
	}

	if resource.Subresources == nil {
		resource.Subresources = []string{}
	}

	return nil
}

// ResourceFromQuery is used for reading resources out of the database.
//
// The `description` field uses `*string` to represent nullability.
type ResourceFromQuery struct {
	ID           int64          `db:"id"`
	Name         string         `db:"name"`
	Description  *string        `db:"description"`
	Path         string         `db:"path"`
	Subresources pq.StringArray `db:"subresources"`
}

// standardize takes a resource returned from a query and turns it into the
// standard form.
func (resourceFromQuery *ResourceFromQuery) standardize() Resource {
	subresources := []string{}
	for _, subresource := range resourceFromQuery.Subresources {
		subresources = append(subresources, formatDbPath(subresource))
	}
	resource := Resource{
		Name:         resourceFromQuery.Name,
		Path:         formatDbPath(resourceFromQuery.Path),
		Subresources: subresources,
	}
	if resourceFromQuery.Description != nil {
		resource.Description = *resourceFromQuery.Description
	}
	return resource
}

// formatPathForDb takes a path from a resource in the database and transforms
// it to the front-end version of the resource path. Inverse of `formatDbPath`.
//
//     formatDbPath("/a/b/c") == "root.a.b.c"
func formatPathForDb(path string) string {
	return "root" + strings.Replace(path, "/", ".", -1)
}

// formatDbPath takes a path from a resource in the database and transforms it
// to the front-end version of the resource path. Inverse of `formatPathForDb`.
//
//     formatDbPath("root.a.b.c") == "/a/b/c"
func formatDbPath(path string) string {
	return strings.Replace(strings.TrimPrefix(path, "root"), ".", "/", -1)
}

// resourceWithPath looks up a resource matching the given path. The database
// schema guarantees such a resource to be unique. Any error returned is
// because of internal database failure.
func resourceWithPath(db *sqlx.DB, path string) (*ResourceFromQuery, error) {
	path = formatPathForDb(path)
	resources := []ResourceFromQuery{}
	stmt := `
		SELECT
			parent.id,
			parent.name,
			parent.path,
			parent.description,
			array(
				SELECT child.path
				FROM resource AS child
				WHERE child.path ~ (
					CAST ((ltree2text(parent.path) || '.*{1}') AS lquery)
				)
			) AS subresources
		FROM resource AS parent
		WHERE parent.path = text2ltree(CAST ($1 AS TEXT))
		GROUP BY parent.id
		LIMIT 1
	`
	err := db.Select(&resources, stmt, path)
	if len(resources) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	resource := resources[0]
	return &resource, nil
}

func listResourcesFromDb(db *sqlx.DB) ([]ResourceFromQuery, error) {
	stmt := `
		SELECT
			parent.id,
			parent.name,
			parent.path,
			parent.description,
			array(
				SELECT child.path
				FROM resource AS child
				WHERE child.path ~ (
					CAST ((ltree2text(parent.path) || '.*{1}') AS lquery)
				)
			) AS subresources
		FROM resource AS parent
		WHERE parent.name != 'root'
		GROUP BY parent.id
	`
	var resources []ResourceFromQuery
	err := db.Select(&resources, stmt)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func (resource *Resource) createInDb(db *sqlx.DB) *ErrorResponse {
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	var resourceID int
	// arborist uses `/` for path separator; ltree in postgres uses `.`
	// -1 means replace everything
	path := strings.Replace(resource.Path, "/", ".", -1)
	path = "root" + path
	if resource.Name == "" {
		segments := strings.Split(path, ".")
		resource.Name = segments[len(segments)-1]
	}
	stmt := "INSERT INTO resource(path, description) VALUES ($1, $2) RETURNING id"
	row := tx.QueryRowx(stmt, path, resource.Description)
	err = row.Scan(&resourceID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		_ = tx.Rollback()
		// this should only fail because the resource was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert resource: resource with this path already exists: `%s`", resource.Path)
		return newErrorResponse(msg, 400, &err)
	}

	err = tx.Commit()
	if err != nil {
		_ = tx.Rollback()
		// TODO: more specific error handling (make sure resource really is
		// invalid)

		// assume that this error is because the resource failed validation on
		// database side, because of missing parent or similar; return 400.
		errMsg := strings.TrimPrefix(err.Error(), "pq: ")
		msg := fmt.Sprintf("couldn't create resource: %s", errMsg)
		return newErrorResponse(msg, 400, &err)
	}

	return nil
}

func (resource *Resource) deleteInDb(db *sqlx.DB) *ErrorResponse {
	stmt := "DELETE FROM resource WHERE path = $1"
	_, err := db.Exec(stmt, formatPathForDb(resource.Path))
	if err != nil {
		// TODO: verify correct error
		msg := fmt.Sprintf("failed to delete resource: resource does not exist: `%s", resource.Path)
		return newErrorResponse(msg, 404, nil)
	}
	return nil
}
