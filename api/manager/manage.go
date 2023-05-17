package manager

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
)

// User Information
// A role must follows the following format: "{satuan_kerja}:{role_function}", e.g. "A1:PP", "A2:Admin PPE"
type userInfo struct {
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
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

	// setup user information
	newUser := &management.User{
		Connection: auth0.String("Username-Password-Authentication"),
		Email:      auth0.String(userinfo.Email),
		Password:   auth0.String(userinfo.Password),
	}

	errList := ValidateRoles(userinfo.Roles)
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

	// Create a new user
	err = Auth0API.User.Create(newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if userinfo.Roles != nil && len(userinfo.Roles) > 0 {
		err = assignRolesHelper(*newUser.ID, userinfo.Roles)
		if err != nil {
			Auth0API.User.Delete(*newUser.ID)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
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

	errList := ValidateRoles(userinfo.Roles)
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
	old_roles, err := Auth0API.User.Roles(userinfo.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if old_roles.Roles != nil && len(old_roles.Roles) > 0 {
		err = Auth0API.User.RemoveRoles(userinfo.ID, old_roles.Roles)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if userinfo.Roles != nil && len(userinfo.Roles) > 0 {
		err = assignRolesHelper(userinfo.ID, userinfo.Roles)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Roles successfully updated"}`))
}

// Handler for Rewrite Roles
// Requires `id` of user and `roles` as part of request body
// will update the roles of user if `roles` is a valid configuration, or do nothing otherwise
func AddRolesHandler(w http.ResponseWriter, r *http.Request) {
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
	if userinfo.Roles == nil || len(userinfo.Roles) == 0 {
		http.Error(w, "To be added roles cannot be empty", http.StatusBadRequest)
		return
	}
	sort.Strings(userinfo.Roles)

	// get old roles for the current user, and check if the roles combined
	// with the future roles will trigger an error
	// Only add old roles that has at least one common "satuan_kerja" as userinfo.Roles
	// Note: old_roles is sorted by role's Name
	old_roles, err := Auth0API.User.Roles(userinfo.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	left_bound := 0
	for i, role := range userinfo.Roles {
		idx := strings.Index(role, ":")
		if idx == -1 {
			continue
		}
		klpd := role[:idx]
		if i > 0 && strings.HasPrefix(userinfo.Roles[i-1], klpd+":") {
			// the role is already added in the previous iteration
			continue
		} else {
			left, right := left_bound, len(old_roles.Roles)-1
			for left < right {
				mid := (left + right) >> 1
				if *old_roles.Roles[mid].Name < klpd+":" {
					left = mid + 1
				} else {
					right = mid
				}
			}
			for ; left < len(old_roles.Roles) && strings.HasPrefix(*old_roles.Roles[left].Name, klpd+":"); left++ {
				userinfo.Roles = append(userinfo.Roles, *old_roles.Roles[left].Name)
			}
			// Since both old_roles and userinfo are sorted, future iterations on userinfo
			// must be in at the greater index.
			left_bound = left
		}
	}

	errList := ValidateRoles(userinfo.Roles)
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

	err = assignRolesHelper(userinfo.ID, userinfo.Roles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Roles successfully updated"}`))
}

// A helper function to assign `rolenames` to user with user id `uid`
//
// Preconditions:
// - all roles in rolenames are valid role
// - a single user with all roles in rolenames does not violate the role rule.
func assignRolesHelper(uid string, rolenames []string) error {
	roles, err := RetrieveRoleByNames(rolenames)
	if err != nil {
		return err
	}

	err = Auth0API.User.AssignRoles(uid, roles)
	if err != nil {
		return err
	}
	return nil
}

func QueryAssignHandler(w http.ResponseWriter, r *http.Request) {
	type queryVar struct {
		AssignerUID string `json:"assigner_uid"`
		CreateRole  string `json:"create_role"`
	}
	var query queryVar
	err := json.NewDecoder(r.Body).Decode(&query)

	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if query.CreateRole == "" {
		http.Error(w, "Assignee UID cannot be empty", http.StatusBadRequest)
		return
	}

	idx := strings.Index(query.CreateRole, ":")
	if idx == -1 {
		http.Error(w, fmt.Sprintf("Role %s is not in correct format", query.CreateRole), http.StatusBadRequest)
	}

	satuanKerja, assigneeRole := query.CreateRole[:idx], query.CreateRole[idx+1:]
	assignerRolelist, err := Auth0API.User.Roles(query.AssignerUID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	left, right := 0, len(assignerRolelist.Roles)-1
	for left < right {
		mid := (left + right) >> 1
		if *assignerRolelist.Roles[mid].Name < satuanKerja+":" {
			left = mid + 1
		} else {
			right = mid
		}
	}

	// only PPE and Agency has the power to create other users
	// PPE can create all but PPE and Auditor
	// Agency can create all but PPE, Auditor, Agency
	assignerPPE, assignerAgency := false, false
	for ; left < len(assignerRolelist.Roles) && strings.HasPrefix(*assignerRolelist.Roles[left].Name, satuanKerja+":"); left++ {
		if *assignerRolelist.Roles[left].Name == satuanKerja+":"+"Admin PPE" {
			assignerPPE = true
		}
		if *assignerRolelist.Roles[left].Name == satuanKerja+":"+"Admin Agency" {
			assignerAgency = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if assignerPPE {
		if assigneeRole == "Admin PPE" || assigneeRole == "Auditor" {
			w.Write([]byte(`{"message": "Action not allowed"}`))
		} else {
			w.Write([]byte(`{"message": "Action allowed"}`))
		}
	} else if assignerAgency {
		if assigneeRole == "Admin PPE" || assigneeRole == "Auditor" || assigneeRole == "Admin Agency" {
			w.Write([]byte(`{"message": "Action not allowed"}`))
		} else {
			w.Write([]byte(`{"message": "Action allowed"}`))
		}
	} else {
		w.Write([]byte(`{"message": "Action not allowed"}`))
	}
}

// Handler for deleting user based on userid
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	var userinfo userInfo
	err := json.NewDecoder(r.Body).Decode(&userinfo)

	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err = Auth0API.User.Delete(userinfo.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"message":"Successfully deleted user"`)))
}
