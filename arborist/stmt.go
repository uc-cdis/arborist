package arborist

import (
	"context"
	"database/sql"
	"github.com/jmoiron/sqlx"
)

type CachedStmts struct {
	db    *sqlx.DB
	stmts map[string]*sqlx.Stmt
}

func NewCachedStmts(db *sqlx.DB) *CachedStmts {
	return &CachedStmts{db, make(map[string]*sqlx.Stmt)}
}

func (s *CachedStmts) Prepare(ctx context.Context, query string) (*sqlx.Stmt, error) {
	stmt, ok := s.stmts[query]
	if !ok {
		// GOTCHA: It's okay not to lock this lazy initialization
		var err error
		stmt, err = s.db.PreparexContext(ctx, query)
		if err != nil {
			return nil, err
		}
		s.stmts[query] = stmt
	}
	return stmt, nil
}

func (s *CachedStmts) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	stmt, err := s.Prepare(ctx, query)
	if err != nil {
		return nil, err
	}
	return stmt.QueryContext(ctx, args...)
}

func (s *CachedStmts) Select(ctx context.Context, query string, dest interface{}, args ...interface{}) error {
	stmt, err := s.Prepare(ctx, query)
	if err != nil {
		return err
	}
	return stmt.SelectContext(ctx, dest, args...)
}
