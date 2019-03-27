package arborist

import (
	"fmt"
	"strconv"
	"strings"
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

// `values` must be castable to string.
func selectInStmt(table string, col string, values []string) string {
	stmt_values := ""
	for _, value := range values {
		stmt_values += fmt.Sprintf("('%s'), ", value)
	}
	stmt_values = strings.TrimRight(stmt_values, ", ")
	stmt := fmt.Sprintf("SELECT %s.* FROM %s INNER JOIN (VALUES %s) values(v) ON %s = v", table, table, stmt_values, col)
	return stmt
}
