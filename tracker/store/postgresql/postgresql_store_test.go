package trackerpostgresql

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/git-yongge/ethgo/tracker/store"
	"github.com/ory/dockertest"
)

func setupDB(t *testing.T) (store.Store, func()) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to docker: %s", err)
	}

	resource, err := pool.Run("postgres", "latest", []string{"POSTGRES_HOST_AUTH_METHOD=trust"})
	if err != nil {
		t.Fatalf("Could not start resource: %s", err)
	}

	endpoint := fmt.Sprintf("postgres://postgres@localhost:%s/postgres?sslmode=disable", resource.GetPort("5432/tcp"))

	// wait for the db to be running
	if err := pool.Retry(func() error {
		db, err := sql.Open("postgres", endpoint)
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		if err := pool.Purge(resource); err != nil {
			t.Fatalf("Could not purge resource: %s", err)
		}
	}

	store, err := NewPostgreSQLStore(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return store, cleanup
}

func TestPostgreSQLStore(t *testing.T) {
	store.TestStore(t, setupDB)
}
