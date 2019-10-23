package arborist

import (
	"github.com/jmoiron/sqlx"
	"net/http"
	"strconv"
)

type Pagination struct {
	Page int `json:"page"`
	PageSize int `json:"page_size"`
	NextPage int `json:"next_page"`
	TotalCount int `json:"total_count"`
}

func SelectWithPagination(db *sqlx.DB, dest interface{}, query string, r *http.Request, args ...interface{}) (*Pagination, error) {
	pagination := &Pagination{}
	vars := r.URL.Query()
	var page string
	var pageSize string
	page = vars.Get("page")
	pageSize = vars.Get("page_size")

	_page, err := strconv.Atoi(page)
	if err != nil {
		if page != "" || pageSize != "" {
			return nil, err
		}
		_page = 0
	}
	_pageSize, err := strconv.Atoi(pageSize)
	if err != nil {
		if page != "" || pageSize != "" {
			return nil, err
		}
		_pageSize = 0
	}
	if _page != 0 && _pageSize != 0 {
		countQuery := `SELECT count(*) FROM (` + query + `) as data`
		var totalCount int
		err = db.Get(&totalCount, countQuery, args...)
		if err != nil {
			return nil, err
		}
		pagination.Page = _page
		pagination.PageSize = _pageSize
		pagination.TotalCount = totalCount
		if _page * _pageSize >= totalCount {
			pagination.NextPage = 0
		} else {
			pagination.NextPage = _page + 1
		}
		query = query + ` LIMIT ` + pageSize + ` OFFSET ` + strconv.Itoa((_page - 1) * _pageSize)
		err := db.Select(dest, query, args...)
		if err != nil {
			return nil, err
		}
		return pagination, nil
	} else {
		err := db.Select(dest, query, args...)
		if err != nil {
			return nil, err
		}
		return nil, nil
	}
}
