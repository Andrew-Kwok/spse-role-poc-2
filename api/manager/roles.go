package manager

import (
	"fmt"
	"sort"

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

// Generate the value of `Division` and `RoleID“
func RoleSetup() error {
	division = make(map[string]string)
	for div, roles := range Hierarchy {
		for _, role := range roles {
			division[role] = div
		}
	}

	rolelist, err := Auth0API.Role.List(
		management.PerPage(100),
	)

	if err != nil {
		return err
	}

	RoleID = make(map[string]string)
	for _, role := range rolelist.Roles {
		RoleID[*role.Name] = *role.ID
	}

	return nil
}

// Takes a list of rolenames which is to be assigned to a single user
// and checks whether such combination of roles violates the ruless
func ValidateRoles(roles [][]string) []error {
	// no roles => no issue
	if roles == nil || len(roles) == 0 {
		return nil
	}

	errors := make([]error, 0)

	// Check existance of organizations
	for _, role := range roles {
		org_name := role[0] + "-" + role[1]
		_, err := Auth0API.Organization.ReadByName(org_name)

		if err != nil {
			errors = append(errors, fmt.Errorf("Error when reading %s. Err: %s", org_name, err))
		}
	}

	if len(errors) != 0 {
		return errors
	}

	sort.Slice(roles, func(i, j int) bool {
		return roles[i][0] < roles[j][0]
	})

	prev_klpd, div := "", ""
	role_PP, role_PPK := false, false

	// division[role] must be the same for all role in roles
	for _, role := range roles {
		if prev_klpd != role[0] {
			prev_klpd, div = role[0], ""
			role_PP, role_PPK = false, false
		}

		role_div, ok := division[role[2]]
		if !ok {
			errors = append(errors, fmt.Errorf("Role Function not found: %s", role[2]))
		} else if div == "" {
			div = role_div
		} else if div != role_div {
			errors = append(errors, fmt.Errorf("User's roles in %s may not cross-function different division: %s, %s", role[0], div, role_div))
		}

		if role[2] == "PP" {
			role_PP = true
		} else if role[2] == "PPK" {
			role_PPK = true
		}

		// special case: a user cannot have PP and PPK at the same time
		if role_PP && role_PPK {
			errors = append(errors, fmt.Errorf("User's roles in %s may not contain PP and PPK at the same time", role[0]))
			break
		}
	}

	if len(errors) != 0 {
		return errors
	}

	if len(errors) != 0 {
		return errors
	}

	return nil
}
