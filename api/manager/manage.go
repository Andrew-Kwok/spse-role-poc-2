package manager

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
)

// Handler for New User Creation
// Requires `email` and `password` input from the request body
// Will create a new user with `roles` if the field is filled.
// See UserInfo to see the structure of roles
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user UserInfo
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if user.Email == "" {
		http.Error(w, "Email cannot be empty", http.StatusBadRequest)
		return
	}
	if user.Password == "" {
		http.Error(w, "Password cannot be empty", http.StatusBadRequest)
		return
	}

	errList := ValidateRolesCombination(user)
	if errList != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		// parse messages into json
		var errListStr []string
		for _, err := range errList {
			errListStr = append(errListStr, err.Error())
		}

		json.NewEncoder(w).Encode(ErrorMessage{
			Errors: errListStr,
		})
		return
	}

	// setup user information
	newUser := &management.User{
		Connection: auth0.String("Username-Password-Authentication"),
		Email:      auth0.String(user.Email),
		Password:   auth0.String(user.Password),

		// User Metadata For Roles
		UserMetadata: &map[string]interface{}{
			"klpd": user.KLPD,
		},
	}

	// Create a new user
	err = Auth0API.User.Create(newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, klpd := range user.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			org, err := Auth0API.Organization.ReadByName(klpd.Name + "-" + satuanKerja.Name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
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

// Handler for Adding Roles to existing user
// Requires `userid` and `roles` input from the request body
// Will update the roles of such user
func AddRolesHandler(w http.ResponseWriter, r *http.Request) {
	var user UserInfo
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if user.ID == "" {
		http.Error(w, "user id cannot be empty", http.StatusBadRequest)
		return
	}
	if user.KLPD == nil {
		http.Error(w, "To be added Roles cannot be empty", http.StatusBadRequest)
		return
	}

	errList := ValidateRolesCombination(user, true)
	if errList != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		// parse messages into json
		var errListStr []string
		for _, err := range errList {
			errListStr = append(errListStr, err.Error())
		}

		json.NewEncoder(w).Encode(ErrorMessage{
			Errors: errListStr,
		})
		return
	}

	for _, klpd := range user.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			org, err := Auth0API.Organization.ReadByName(klpd.Name + "-" + satuanKerja.Name)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			Auth0API.Organization.AddMembers(*org.ID, []string{user.ID})

			roleIDs := make([]string, 0)
			for _, role := range satuanKerja.Roles {
				roleIDs = append(roleIDs, RoleID[role])
			}
			Auth0API.Organization.AssignMemberRoles(*org.ID, user.ID, roleIDs)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"message":"Roles successfully updated for user with ID: %s"}`, user.ID)))
}

// Handler for Adding Roles to existing user
// The Existence/Naming of each role is checked
// However if the role doesn't exist in a user, it will be ignored
func DeleteRolesHandler(w http.ResponseWriter, r *http.Request) {
	var user UserInfo
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if user.ID == "" {
		http.Error(w, "user id cannot be empty", http.StatusBadRequest)
		return
	}
	if user.KLPD == nil {
		http.Error(w, "To be deleted Roles cannot be empty", http.StatusBadRequest)
		return
	}

	var errors []error
	// Validate the roles exist
	for _, klpd := range user.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			org_name := klpd.Name + "-" + satuanKerja.Name
			_, err := Auth0API.Organization.ReadByName(org_name)
			if err != nil {
				errors = append(errors, fmt.Errorf("Error when reading %s. Err: %s", org_name, err))
				continue
			}

			for _, role := range satuanKerja.Roles {
				_, ok := RoleID[role]
				if !ok {
					errors = append(errors, fmt.Errorf("Role Function in %s-%s not found: %s", klpd.Name, satuanKerja.Name, role))
				}
			}
		}
	}

	if len(errors) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		// parse messages into json
		var errListStr []string
		for _, err := range errors {
			errListStr = append(errListStr, err.Error())
		}

		json.NewEncoder(w).Encode(ErrorMessage{
			Errors: errListStr,
		})
		return
	}

	for _, klpd := range user.KLPD {
		for _, satuanKerja := range klpd.SatuanKerja {
			org_name := klpd.Name + "-" + satuanKerja.Name
			org, err := Auth0API.Organization.ReadByName(org_name)
			if err != nil {
				http.Error(w, fmt.Sprintf("Error when reading %s. Err: %s", org_name, err), http.StatusInternalServerError)
				continue
			}

			roleIDs := make([]string, 0)
			for _, role := range satuanKerja.Roles {
				roleIDs = append(roleIDs, RoleID[role])
			}
			Auth0API.Organization.DeleteMemberRoles(*org.ID, user.ID, roleIDs)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"message":"Roles successfully updated for user with ID: %s"}`, user.ID)))
}
