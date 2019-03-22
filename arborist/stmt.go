package arborist

import (
	"database/sql"
	"github.com/jmoiron/sqlx"
)

type CachedStmts struct {
	db    *sqlx.DB
	stmts map[string]*sql.Stmt
}

func NewCachedStmts(db *sqlx.DB) *CachedStmts {
	return &CachedStmts{db, make(map[string]*sql.Stmt)}
}

func (s *CachedStmts) Prepare(query string) (*sql.Stmt, error) {
	stmt, ok := s.stmts[query]
	if !ok {
		// GOTCHA: It's okay not to lock this lazy initialization
		var err error = nil
		stmt, err = s.db.Prepare(query)
		if err != nil {
			return nil, err
		}
		s.stmts[query] = stmt
	}
	return stmt, nil
}

func (s *CachedStmts) Query(query string, args ...interface{}) (*sql.Rows, error) {
	stmt, err := s.Prepare(query)
	if err != nil {
		return nil, err
	}
	return stmt.Query(args...)
}
