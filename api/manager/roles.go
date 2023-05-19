package manager

import (
	"fmt"
	"strings"

	"github.com/auth0/go-auth0/management"
)

// A role has the format of `satuanKerja`:`	`
//
// # Hierarchy maps the division of each role
//
// Rule for role assignments
// 1. A single user in the same KLPD is not allowed to cross-function, i.e. has roles in different division
// 2. For "Pelaku Pengadaan LPSE", a single user in the same KLPD cannot be both "PPK" and "PP"
// 3. A single user may have different function in different "KLPD"
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
func ValidateRolesCombination(user UserInfo, keepOldRolesOpt ...bool) []error {
	keepOldRoles := false
	if len(keepOldRolesOpt) == 0 {

	} else if len(keepOldRolesOpt) == 1 {
		keepOldRoles = keepOldRolesOpt[0]
	} else {
		return []error{fmt.Errorf("Invalid Number of Arguments. Expected max 1. Got %d", len(keepOldRolesOpt))}
	}

	errors := make([]error, 0)

	for _, klpd := range user.KLPD {
		div := ""
		role_PP, role_PPK := false, false

		if keepOldRoles {
			// TODO. orgList is sorted by Name, implement binary search
			orgList, err := Auth0API.Organization.List()
			if err != nil {
				errors = append(errors, fmt.Errorf("Error when reading organization names. Err: %s", err))
			}

			for _, org := range orgList.Organizations {
				if strings.HasPrefix(*org.Name, klpd.Name+"-") {
					oldRoleList, err := Auth0API.Organization.MemberRoles(*org.ID, user.ID)

					if err != nil {
						if strings.Contains(err.Error(), "404") {

						} else {
							errors = append(errors, fmt.Errorf("Error when reading user roles in %s. Err: %s", *org.DisplayName, err))
							continue
						}
					} else {
						// oldRoleList was a valid user configuration
						for _, role := range oldRoleList.Roles {
							role_div, ok := division[*role.Name]
							if !ok {
								errors = append(errors, fmt.Errorf("Role Function not found: %s", *role.Name))
							} else if div == "" {
								div = role_div
							} else if div != role_div {
								errors = append(errors, fmt.Errorf("User's roles in %s may not cross-function different division: %s, %s", klpd, div, role_div))
								break
							}

							if *role.Name == "PP" {
								role_PP = true
							} else if *role.Name == "PPK" {
								role_PPK = true
							}
						}
					}
				}

				// Since the role configuration was valid, if any of the following is true
				// it is irrelevant to check more.
				if div == "Pengelola LPSE" || div == "Auditor" {
					break
				} else if div == "Pelaku Pengadaan LPSE" && (role_PP || role_PPK) {
					break
				}
			}
		}

		if len(errors) != 0 {
			continue
		}

		for _, satuanKerja := range klpd.SatuanKerja {
			// Check existance of organizations
			org_name := klpd.Name + "-" + satuanKerja.Name
			_, err := Auth0API.Organization.ReadByName(org_name)
			if err != nil {
				errors = append(errors, fmt.Errorf("Error when reading %s. Err: %s", org_name, err))
				continue
			}

			if len(satuanKerja.Roles) == 0 {
				errors = append(errors, fmt.Errorf("Role assignment cannot be empty for KLPD %s Satuan-Kerja %s", klpd.Name, satuanKerja.Name))
				continue
			}

			for _, role := range satuanKerja.Roles {
				role_div, ok := division[role]
				if !ok {
					errors = append(errors, fmt.Errorf("Role Function not found: %s", role))
				} else if div == "" {
					div = role_div
				} else if div != role_div {
					errors = append(errors, fmt.Errorf("User's roles in %s may not cross-function different division: %s, %s", klpd, div, role_div))
					break
				}

				if role == "PP" {
					role_PP = true
				} else if role == "PPK" {
					role_PPK = true
				}
			}
		}

		// special case: a user cannot have PP and PPK at the same time
		if role_PP && role_PPK {
			errors = append(errors, fmt.Errorf("User's roles in %s may not contain PP and PPK at the same time", klpd))
			break
		}
	}

	if len(errors) != 0 {
		return errors
	}

	return nil
}
