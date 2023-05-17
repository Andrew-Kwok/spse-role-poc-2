package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"spse-role-poc/api/manager"
)

// A middleware to validate whether the assigner is allowed to perform such action
func ValidateRoles(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the original request body
		buf, _ := ioutil.ReadAll(r.Body)
		rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
		rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))

		// data type to extract token and roles from the request body
		type token_and_roles struct {
			Token string   `json:"token"`
			Roles []string `json:"roles"`
		}

		var data token_and_roles
		err := json.NewDecoder(rdr1).Decode(&data)

		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		req, err := http.NewRequest("GET", "https://"+os.Getenv("AUTH0_DOMAIN")+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+data.Token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Retrieve only the sub(assigner uid) key from the response body
		type jsonResponse struct {
			Sub string `json:"sub"`
		}
		var response jsonResponse
		err = json.Unmarshal(body, &response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		assigner_uid := response.Sub

		assignerRoleList, err := manager.Auth0API.User.Roles(assigner_uid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		// assignerPPE[satuanKerja] is true IFF assigner has "Admin PPE" role in "satuanKerja"
		assignerPPE := make(map[string]bool)

		// assignerAgency[satuanKerja] is true IFF assigner has "Admin Agency" role in "satuanKerja"
		assignerAgency := make(map[string]bool)

		for _, role := range assignerRoleList.Roles {
			idx := strings.LastIndex(*role.Name, ":")
			if idx == -1 {
				continue
			}
			satuanKerja := (*role.Name)[:idx]
			roleFunction := (*role.Name)[idx+1:]

			if roleFunction == "Admin PPE" {
				assignerPPE[satuanKerja] = true
			} else if roleFunction == "Admin Agency" {
				assignerAgency[satuanKerja] = true
			}
		}

		for _, assignee_role := range data.Roles {
			idx := strings.LastIndex(assignee_role, ":")
			if idx == -1 {
				http.Error(w, fmt.Sprintf("Role %s is not in correct format", assignee_role), http.StatusBadRequest)
			}
			satuanKerja := assignee_role[:idx]
			roleFunction := assignee_role[idx+1:]

			if roleFunction == "Admin PPE" || roleFunction == "Auditor" {
				http.Error(w, "Action not allowed", http.StatusForbidden)
				return
			} else if roleFunction == "Admin Agency" {
				if !assignerPPE[satuanKerja] {
					http.Error(w, "Action not allowed", http.StatusForbidden)
					return
				}
			} else {
				if !assignerPPE[satuanKerja] && !assignerAgency[satuanKerja] {
					http.Error(w, "Action not allowed", http.StatusForbidden)
					return
				}
			}
		}

		// Copy back the original data to request body
		r.Body = rdr2
		next.ServeHTTP(w, r)
	})
}
