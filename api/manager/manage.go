package manager

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
)

// User Information
//
// A role must follows the following format: "{satuan_kerja}:{role_function}", e.g. "A1:PP", "A2:Admin PPE"
type userInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	KLPD     []struct {
		Name        string `json:"name"`
		SatuanKerja []struct {
			Name  string   `json:"name"`
			Roles []string `json:"roles"`
		} `json:"satuan-kerja"`
	} `json:"klpd"`
}

// struct to store a list of error message
type error_message struct {
	Errors []string `"json:errors"`
}

// Handler for New User Creation
// Requires `email` and `password` input from the request body
// Will create a new user with `roles` if the field is filled.
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var userinfo userInfo
	err := json.NewDecoder(r.Body).Decode(&userinfo)

	if err != nil {
		log.Fatal(err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if userinfo.Email == "" {
		http.Error(w, "Email cannot be empty", http.StatusBadRequest)
		return
	}
	if userinfo.Password == "" {
		http.Error(w, "Password cannot be empty", http.StatusBadRequest)
		return
	}

	// Check Validity of Role Combination
	roles := make([][]string, 0)
	for _, klpd := range userinfo.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			for _, role := range satuanKerja.Roles {
				roles = append(roles, []string{klpd.Name, satuanKerja.Name, role})
			}
		}
	}

	errList := ValidateRoles(roles)
	if errList != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		// parse messages into json
		var errListStr []string
		for _, err := range errList {
			errListStr = append(errListStr, err.Error())
		}

		json.NewEncoder(w).Encode(error_message{
			Errors: errListStr,
		})
		return
	}

	// setup user information
	newUser := &management.User{
		Connection: auth0.String("Username-Password-Authentication"),
		Email:      auth0.String(userinfo.Email),
		Password:   auth0.String(userinfo.Password),
	}

	// Create a new user
	err = Auth0API.User.Create(newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, klpd := range userinfo.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			org, err := Auth0API.Organization.ReadByName(klpd.Name + "-" + satuanKerja.Name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			Auth0API.Organization.AddMembers(*org.ID, []string{*newUser.ID})

			roleIDs := make([]string, 0)
			for _, role := range satuanKerja.Roles {
				roleIDs = append(roleIDs, RoleID[role])
			}
			Auth0API.Organization.AssignMemberRoles(*org.ID, *newUser.ID, roleIDs)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(fmt.Sprintf(`{"message":"New user successfully creaded with ID: %s"}`, *newUser.ID)))
}

// Handler for Rewrite Roles
// Requires `id` of user and `roles` as part of request body
// will update the roles of user if `roles` is a valid configuration, or do nothing otherwise
func RewriteRolesHandler(w http.ResponseWriter, r *http.Request) {
	var userinfo userInfo
	err := json.NewDecoder(r.Body).Decode(&userinfo)

	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if userinfo.ID == "" {
		http.Error(w, "user id cannot be empty", http.StatusBadRequest)
		return
	}

	roles := make([][]string, 0)
	for _, klpd := range userinfo.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			for _, role := range satuanKerja.Roles {
				roles = append(roles, []string{klpd.Name, satuanKerja.Name, role})
			}
		}
	}

	errList := ValidateRoles(roles)
	if errList != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		// parse messages into json
		var errListStr []string
		for _, err := range errList {
			errListStr = append(errListStr, err.Error())
		}

		json.NewEncoder(w).Encode(error_message{
			Errors: errListStr,
		})
		return
	}

	// Remove all old roles
	old_orgs, err := Auth0API.User.Organizations(userinfo.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, old_org := range old_orgs.Organizations {
		old_roles, err := Auth0API.Organization.MemberRoles(*old_org.ID, userinfo.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		old_roles_ids := make([]string, 0)
		for _, old_role := range old_roles.Roles {
			old_roles_ids = append(old_roles_ids, *old_role.ID)
		}

		if len(old_roles_ids) == 0 {
			continue
		}

		err = Auth0API.Organization.DeleteMemberRoles(*old_org.ID, userinfo.ID, old_roles_ids)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	for _, klpd := range userinfo.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			org, err := Auth0API.Organization.ReadByName(klpd.Name + "-" + satuanKerja.Name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			Auth0API.Organization.AddMembers(*org.ID, []string{userinfo.ID})

			roleIDs := make([]string, 0)
			for _, role := range satuanKerja.Roles {
				roleIDs = append(roleIDs, RoleID[role])
			}
			Auth0API.Organization.AssignMemberRoles(*org.ID, userinfo.ID, roleIDs)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Roles successfully updated"}`))
}
