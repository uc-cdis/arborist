package arborist_test

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/uc-cdis/arborist/arborist"
)

// The health check must not wait for a connection from the main pool: when
// every connection is busy, the database is still reachable, and failing the
// probe would take the pod out of service for being busy.
func TestHealthWithBusyPool(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	db.SetMaxOpenConns(1)
	healthDB := openTestDB(t)
	defer healthDB.Close()
	healthDB.SetMaxOpenConns(1)

	server, err := arborist.NewServer().
		WithLogger(log.New(io.Discard, "", 0)).
		WithJWTApp(&mockJWTApp{}).
		WithDB(db).
		WithHealthDB(healthDB).
		Init()
	require.NoError(t, err)
	handler := server.MakeRouter(io.Discard)

	// take the main pool's only connection
	conn, err := db.Connx(context.Background())
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest("GET", "/health", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "health check should not wait on the busy main pool; got %s", w.Body.String())
}
