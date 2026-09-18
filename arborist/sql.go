package arborist

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// multiInsertStmt generates a string for a SQL command to insert multiple rows
// into a table.
//
//     multiInsertStmt("table(col1, col2)", 2)
//     == "INSERT INTO table(col1, col2) VALUES ($1, $2), ($3, $4)"
//
func multiInsertStmt(table string, n_rows int) string {
	parse_values := strings.Split(table, "(")
	half_parsed := parse_values[len(parse_values)-1]
	parse_values = strings.Split(half_parsed, ")")
	values := strings.Split(parse_values[0], ",")
	n_values := len(values)

	rowsString := ""

	x := 1
	for i := 1; i <= n_rows; i++ {
		rowsString += "("
		for j := 1; j <= n_values; j++ {
			rowsString += "$"
			rowsString += strconv.Itoa(x)
			rowsString += ", "
			x++
		}
		rowsString = strings.TrimRight(rowsString, ", ")
		rowsString += "), "
	}
	rowsString = strings.TrimRight(rowsString, ", ")

	return fmt.Sprintf("INSERT INTO %s VALUES %s", table, rowsString)
}

// selectInStmt builds a query selecting every row of `table` whose `col` matches
// any of `values`, along with the bind argument carrying those values. `table`
// and `col` are interpolated and must be trusted (never user input); `values` is
// always bound as a parameter, never interpolated into the SQL.
func selectInStmt(table string, col string, values []string) (string, interface{}) {
	stmt := fmt.Sprintf("SELECT %s.* FROM %s WHERE %s = ANY($1)", table, table, col)
	return stmt, pq.Array(values)
}

// transactify lets you pass a `sqlx.DB` to a function which uses a `sqlx.Tx`,
// and handles opening and committing the transaction. The function passed to
// transactify can chain multiple other functions together into one
// transaction. If a non-nil error response is returned from the called
// function, the transaction is rolled back. It's up to the called function to
// error out early if that's preferred; the rolling-back happens at the end.
func transactify(db *sqlx.DB, call func(tx *sqlx.Tx) *ErrorResponse) *ErrorResponse {
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}
	errResponse := call(tx)
	if errResponse != nil {
		errResponse.log.Info("rolling back transaction")
		_ = tx.Rollback()
		return errResponse
	}
	err = tx.Commit()
	if err != nil {
		msg := fmt.Sprintf("couldn't commit database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}
