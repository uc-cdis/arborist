package arborist

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// A note on the fields here: either the resource must have been created
// through the subresources field of a parent resource, in which case the path
// is formed from the parent path joined with this resource's name, or with an
// explicit full path here.

type ResourceIn struct {
	Name         string       `json:"name"`
	Path         string       `json:"path"`
	Description  string       `json:"description"`
	Subresources []ResourceIn `json:"subresources"`
}

type ResourceOut struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Tag          string   `json:"tag"`
	Description  string   `json:"description"`
	Subresources []string `json:"subresources"`
	Namespace	 bool	  `json:"namespace"`
}

var regPercent *regexp.Regexp = regexp.MustCompile(`%`)
var regSlashEncoded *regexp.Regexp = regexp.MustCompile(`%2F`)

func UnderscoreEncode(decoded string) string {
	// Per https://www.ietf.org/rfc/rfc3986.txt, there are the following
	// unreserved characters (aside from alphanumeric and underscore) which do
	// not urlencode:
	//   - `-`
	//   - `.`
	//   - `~`
	// Percent encoding uses hexadecimal, which we mustn't conflict with. So we
	// use some made-up codes for these which will not overlap.
	encoded := decoded
	encoded = strings.ReplaceAll(encoded, "_", "_S0")
	encoded = strings.ReplaceAll(encoded, "-", "_S1")
	encoded = strings.ReplaceAll(encoded, ".", "_S2")
	encoded = strings.ReplaceAll(encoded, "~", "_S3")
	encoded = url.QueryEscape(encoded)
	// turn the slashes *back*, we only want to "underscore-encode" other stuff
	encoded = strings.ReplaceAll(encoded, "%2F", "/")
	// finally we turn the % symbols into __ which ltree is OK with
	encoded = strings.ReplaceAll(encoded, "%", "__")
	return encoded
}

func UnderscoreDecode(encoded string) string {
	// undo the steps from UnderscoreEncode
	decoded := encoded
	decoded = strings.ReplaceAll(decoded, "_S1", "-")
	decoded = strings.ReplaceAll(decoded, "_S2", ".")
	decoded = strings.ReplaceAll(decoded, "_S3", "~")
	decoded = strings.ReplaceAll(decoded, "__", "%")
	decoded = strings.ReplaceAll(decoded, "_S0", "_")
	decoded, _ = url.QueryUnescape(decoded)
	return decoded
}

// NOTE: the resource unmarshalling, because the resources can be specified
// with either the name + endpoint path, or the full path in the JSON input, is
// not able to validate all cases precisely. The unmarshalling will pass as
// long as either the name or the path is provided, which may require
// additional validation where this is called.
func (resource *ResourceIn) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}

	// delete fields which should be ignored in user input
	delete(fields, "tag")

	optionalFieldsPath := map[string]struct{}{
		"name":         struct{}{},
		"tag":          struct{}{},
		"description":  struct{}{},
		"subresources": struct{}{},
	}
	errPath := validateJSON("resource", resource, fields, optionalFieldsPath)
	optionalFieldsName := map[string]struct{}{
		"path":         struct{}{},
		"tag":          struct{}{},
		"description":  struct{}{},
		"subresources": struct{}{},
	}
	errName := validateJSON("resource", resource, fields, optionalFieldsName)
	if errPath != nil && errName != nil {
		return errPath
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the Resource to.
	type loader ResourceIn
	err = json.Unmarshal(data, (*loader)(resource))
	if err != nil {
		return err
	}

	if resource.Subresources == nil {
		resource.Subresources = []ResourceIn{}
	}

	return nil
}

// ResourceFromQuery is used for reading resources out of the database.
//
// The `description` field uses `*string` to represent nullability.
type ResourceFromQuery struct {
	ID           int64          `db:"id"`
	Name         string         `db:"name"`
	Tag          string         `db:"tag"`
	Description  *string        `db:"description"`
	Path         string         `db:"path"`
	Subresources pq.StringArray `db:"subresources"`
	Namespace	 bool			`db:"namespace"`
}

// standardize takes a resource returned from a query and turns it into the
// standard form.
func (resourceFromQuery *ResourceFromQuery) standardize() ResourceOut {
	subresources := []string{}
	for _, subresource := range resourceFromQuery.Subresources {
		subresources = append(subresources, formatDbPath(subresource))
	}
	resource := ResourceOut{
		Name:         UnderscoreDecode(resourceFromQuery.Name),
		Path:         UnderscoreDecode(formatDbPath(resourceFromQuery.Path)),
		Tag:          resourceFromQuery.Tag,
		Subresources: subresources,
		Namespace:	  resourceFromQuery.Namespace,
	}
	if resourceFromQuery.Description != nil {
		resource.Description = *resourceFromQuery.Description
	}
	return resource
}

// FormatPathForDb takes a front-end version of a resource path and transforms
// it to its database version. Inverse of `formatDbPath`.
//
//     FormatPathForDb("/a/b/c") == "a.b.c"
func FormatPathForDb(path string) string {
	// -1 means replace everything
	result := strings.TrimLeft(strings.Replace(UnderscoreEncode(path), "/", ".", -1), ".")
	return result
}

// formatDbPath takes a path from a resource in the database and transforms it
// to the front-end version of the resource path. Inverse of `FormatPathForDb`.
//
//     formatDbPath("a.b.c") == "/a/b/c"
func formatDbPath(path string) string {
	// -1 means replace everything
	return UnderscoreDecode("/" + strings.Replace(path, ".", "/", -1))
}

// resourceWithPath looks up a resource matching the given path. The database
// schema guarantees such a resource to be unique. Any error returned is because
// of internal database failure.
func resourceWithPath(db *sqlx.DB, path string) (*ResourceFromQuery, error) {
	path = FormatPathForDb(path)
	resources := []ResourceFromQuery{}
	stmt := `
		SELECT
			parent.id,
			parent.name,
			parent.path,
			parent.tag,
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
		// not found
		return nil, nil
	}
	if err != nil {
		// query broken
		return nil, err
	}
	resource := resources[0]
	return &resource, nil
}

// resourceWithTag looks up a resource matching the given tag. The database
// schema guarantees such a resource to be unique. Any error returned is because
// of internal database failure.
func resourceWithTag(db *sqlx.DB, tag string) (*ResourceFromQuery, error) {
	resources := []ResourceFromQuery{}
	stmt := `
		SELECT
			parent.id,
			parent.name,
			parent.path,
			parent.tag,
			parent.description,
			array(
				SELECT child.path
				FROM resource AS child
				WHERE child.path ~ (
					CAST ((ltree2text(parent.path) || '.*{1}') AS lquery)
				)
			) AS subresources
		FROM resource AS parent
		WHERE parent.tag = $1
	`
	err := db.Select(&resources, stmt, tag)
	if len(resources) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	resource := resources[0]
	return &resource, nil
}

func resourceWithNamespace(db *sqlx.DB, path string) ([]ResourceFromQuery, error) {
	path = strings.Replace(path, string('/'), string('.'), -1)
	if strings.HasPrefix(path, string('.')) {
		path = path[1:]
	}
	stmt := `
		SELECT
			parent.id,
			parent.name,
			parent.path,
			parent.tag,
			parent.description,
			array(
				SELECT child.path
				FROM resource AS child
				WHERE child.path ~ (
					CAST ((ltree2text(parent.path) || '.*{1}') AS lquery)
				)
			) AS subresources
		FROM resource AS parent
	`
	if path == "" {
		stmt += "WHERE parent.namespace = true AND nlevel(parent.path) = 1"
	} else if path == "default" {
		stmt += `
		WHERE parent.namespace = false 
		AND NOT EXISTS (SELECT 1 FROM resource AS root WHERE root.namespace = true AND root.path @> parent.path)`
	} else {
		stmt += `WHERE text2ltree(CAST ('` + path + `' AS TEXT)) @> parent.path AND parent.path != '` + path + `'`
	}
	stmt += " GROUP BY parent.id"
	var resources []ResourceFromQuery
	err := db.Select(&resources, stmt)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func listResourcesFromDb(db *sqlx.DB) ([]ResourceFromQuery, error) {
	stmt := `
		SELECT
			parent.id,
			parent.name,
			parent.path,
			parent.tag,
			parent.description,
			parent.namespace,
			array(
				SELECT child.path
				FROM resource AS child
				WHERE child.path ~ (
					CAST ((ltree2text(parent.path) || '.*{1}') AS lquery)
				)
			) AS subresources
		FROM resource AS parent
		GROUP BY parent.id
	`
	var resources []ResourceFromQuery
	err := db.Select(&resources, stmt)
	if err != nil {
		return nil, err
	}
	return resources, nil
}

func (resource *ResourceIn) createInDb(tx *sqlx.Tx) *ErrorResponse {
	errResponse := resource.createRecursively(tx)
	if errResponse != nil {
		return errResponse
	}
	return nil
}

func (resource *ResourceIn) createRecursively(tx *sqlx.Tx) *ErrorResponse {
	// arborist uses `/` for path separator; ltree in postgres uses `.`
	path := FormatPathForDb(resource.Path)
	stmt := "INSERT INTO resource(path, description) VALUES ($1, $2)"
	_, err := tx.Exec(stmt, path, resource.Description)
	if err != nil {
		// should add more checking here to guarantee the correct error
		// TODO (rudyardrichter, 2019-06-04): rollback probably not necessary,
		// since this is probably called with `transactify`
		_ = tx.Rollback()
		// this should only fail because the resource was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert resource: resource with this path already exists: `%s`", resource.Path)
		return newErrorResponse(msg, 409, &err)
	}
	// TODO (rudyardrichter, 2019-04-09): optimize (could be non-recursive)
	for _, subresource := range resource.Subresources {
		// fill out subresource paths based on the current name
		if subresource.Path == "" {
			subresource.Path = resource.Path + "/" + subresource.Name
		}
		errResponse := subresource.createRecursively(tx)
		if errResponse != nil {
			return errResponse
		}
	}
	return nil
}

func (resource *ResourceIn) deleteInDb(tx *sqlx.Tx) *ErrorResponse {
	if resource.Path == "" {
		msg := "resource missing required field `path`"
		return newErrorResponse(msg, 400, nil)
	}
	stmt := "DELETE FROM resource WHERE path = $1"
	_, err := tx.Exec(stmt, FormatPathForDb(resource.Path))
	if err != nil {
		// resource already doesn't exist; this is fine
		return nil
	}
	return nil
}

// addPathAndName fills out the path or name using the parent path. Resources
// can input only `name` instead of `path` in the JSON body, and use the path
// in the URL instead, so this fills out the path if necessary.
func (resource *ResourceIn) addPath(parent string) *ErrorResponse {
	if resource.Path == "" {
		if resource.Name == "" {
			err := missingRequiredField("resource", "name")
			errResponse := newErrorResponse(err.Error(), 400, &err)
			errResponse.log.Info(err.Error())
			return errResponse
		}
		resource.Path = parent + "/" + resource.Name
	}
	// the resource creation is ok with having duplicate slashes but it'll
	// mess with the queries using this resource, so let's clean it up now
	resource.Path = regSlashes.ReplaceAllLiteralString(resource.Path, "/")
	return nil
}

func (resource *ResourceIn) overwriteInDb(tx *sqlx.Tx) *ErrorResponse {
	// arborist uses `/` for path separator; ltree in postgres uses `.`
	path := FormatPathForDb(resource.Path)
	stmt := "INSERT INTO resource(path) VALUES ($1) ON CONFLICT DO NOTHING"
	_, err := tx.Exec(stmt, path)
	if err != nil {
		// should add more checking here to guarantee the correct error
		// TODO (rudyardrichter, 2019-06-04): rollback probably not necessary,
		// since this is probably called with `transactify`
		_ = tx.Rollback()
		// this should only fail because the resource was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert resource: resource with this path already exists: `%s`", resource.Path)
		return newErrorResponse(msg, 409, &err)
	}

	// update description
	stmt = "UPDATE resource SET description = $2 WHERE path = $1"
	_, err = tx.Exec(stmt, path, resource.Description)

	// delete the subresources not in the new request
	if len(resource.Subresources) > 0 {
		subPathsKeep := []string{}
		for _, subresource := range resource.Subresources {
			subresource.addPath(resource.Path)
			subpath := fmt.Sprintf("'%s'", FormatPathForDb(subresource.Path))
			subPathsKeep = append(subPathsKeep, subpath)
		}
		stmtFormat := `
			DELETE FROM resource
			WHERE (
				path != $1
				AND path ~ (CAST ((ltree2text($1) || '.*{1}') AS lquery))
				AND path NOT IN (%s)
			)
		`
		stmt = fmt.Sprintf(stmtFormat, strings.Join(subPathsKeep, ", "))
		_, _ = tx.Exec(stmt, path)
	} else {
		stmt := `
			DELETE FROM resource
			WHERE path != $1 AND path ~ (CAST ((ltree2text($1) || '.*{1}') AS lquery))
		`
		_, _ = tx.Exec(stmt, path)
	}

	// TODO (rudyardrichter, 2019-04-09): optimize (could be non-recursive)
	for _, subresource := range resource.Subresources {
		// fill out subresource paths based on the current name
		errResponse := subresource.addPath(resource.Path)
		if errResponse != nil {
			return errResponse
		}
		errResponse = subresource.overwriteInDb(tx)
		if errResponse != nil {
			return errResponse
		}
	}

	return nil
}
