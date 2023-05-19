package router

import (
	"net/http"

	"github.com/go-chi/chi"

	"spse-role-poc/api/manager"
	"spse-role-poc/api/middleware"
)

func New() http.Handler {
	r := chi.NewRouter()

	// publicly accessible - to test the api is responding
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Hello World!"}`))
	})

	// user functions
	r.Post("/create", manager.CreateUserHandler)
	r.Patch("/addroles", manager.AddRolesHandler)
	r.Patch("/deleteroles", manager.DeleteRolesHandler)

	r.Route("/", func(r chi.Router) {
		r.Use(middleware.ValidateRoleAuthority)
		r.Post("/create-protected", manager.CreateUserHandler)
		r.Patch("/addroles-protected", manager.AddRolesHandler)
		r.Patch("/deleteroles-protected", manager.DeleteRolesHandler)
	})

	return r
}
