package manager

import (
	"fmt"
	"sort"
	"strings"

	"github.com/auth0/go-auth0/management"
)

type Pair struct {
	First  string
	Second string
}

// A role has the format of `satuanKerja`:`	`
//
// # Hierarchy maps the division of each role
//
// Rule for role assignments
// 1. A single user is not allowed to cross-function, i.e. has roles in different division
// 2. For "Pelaku Pengadaan LPSE", a single user cannot be both "PPK" and "PP"
// 3. A single user may have different function in different "satuan-kerja"
var Hierarchy = map[string][]string{
	"Pengelola LPSE":        {"Admin PPE", "Admin Agency", "Verifikator", "Helpdesk"},
	"Pelaku Pengadaan LPSE": {"PPK", "KUPBJ", "Anggota Pokmil", "PP"},
	"Auditor":               {"Auditor"},
}

var division map[string]string // Division maps each `role name` to its division (parent)
var RoleID map[string]string   // RoleID maps each `role name` to its `role id`

// Generate the value of `Division“
func RoleSetup() error {
	division = make(map[string]string)
	for div, roles := range Hierarchy {
		for _, role := range roles {
			division[role] = div
		}
	}
	return nil
}

// Retrieve the list role objects for each rolename in rolenames and returns
// Preconditions:
// - each rolename in rolenames is a valid rolename and exists in Auth0's roles
// Note:
// - Auth0API.Role.List() Returns a list of roles sorted by role.Name
func RetrieveRoleByNames(rolenames []string) ([]*management.Role, error) {
	sort.Strings(rolenames)

	// Note: List only returns by default 50 roles per page and maximum 100 per page
	rolelist, err := Auth0API.Role.List(
		management.PerPage(100),
	)
	if err != nil {
		return nil, err
	}

	left_bound := 0
	roles := make([]*management.Role, 0)
	for _, rolename := range rolenames {
		left, right := left_bound, len(rolelist.Roles)-1
		for left < right {
			mid := (left + right) >> 1
			if *rolelist.Roles[mid].Name < rolename {
				left = mid + 1
			} else {
				right = mid
			}
		}
		roles = append(roles, rolelist.Roles[left])
		left_bound = left
	}
	return roles, nil
}

// Takes a list of rolenames which is to be assigned to a single user
// and checks whether such combination of roles violates the ruless
func ValidateRoles(rolenames []string) []error {
	// no roles => no issue
	if rolenames == nil || len(rolenames) == 0 {
		return nil
	}

	errors := make([]error, 0)
	rolenames_by_KLPD := make(map[string][]Pair)
	for _, rolename := range rolenames {
		parts := strings.Split(rolename, ":")
		if len(parts) != 3 {
			errors = append(errors, fmt.Errorf("Role %s is not in correct format", rolename))
			continue
		}

		KLPD, satuanKerja, roleFunction := parts[0], parts[1], parts[2]
		rolenames_by_KLPD[KLPD] = append(rolenames_by_KLPD[KLPD], Pair{First: satuanKerja, Second: roleFunction})
	}

	if len(errors) != 0 {
		return errors
	}

	for KLPD, rolenames := range rolenames_by_KLPD {
		// division[role] must be the same for all role in roles
		var div string = ""
		role_PP, role_PPK := false, false

		for _, rolename := range rolenames {
			rolename_div, ok := division[rolename.Second]
			if !ok {
				errors = append(errors, fmt.Errorf("Role Function not found: %s", rolename.Second))
			} else if div == "" {
				div = rolename_div
			} else if div != rolename_div {
				errors = append(errors, fmt.Errorf("User's roles in %s may not cross-function different division: %s, %s", KLPD, div, rolename_div))
			}

			if rolename.Second == "PP" {
				role_PP = true
			} else if rolename.Second == "PPK" {
				role_PPK = true
			}
		}

		// special case: a user cannot have PP and PPK at the same time
		if role_PP && role_PPK {
			errors = append(errors, fmt.Errorf("User's roles in %s may not contain PP and PPK at the same time", KLPD))
		}
	}

	if len(errors) != 0 {
		return errors
	}

	return nil
}
