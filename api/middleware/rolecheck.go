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
func ValidateRoleAuthority(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the original request body
		buf, _ := ioutil.ReadAll(r.Body)
		rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
		rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))

		token := r.Header.Get("Token")

		// data type to extract token and roles from the request body
		type Roles struct {
			KLPD []struct {
				Name        string `json:"name"`
				SatuanKerja []struct {
					Name  string   `json:"name"`
					Roles []string `json:"roles"`
				} `json:"satuan-kerja"`
			} `json:"klpd"`
		}

		var data Roles
		err := json.NewDecoder(rdr1).Decode(&data)

		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		req, err := http.NewRequest("GET", "https://"+os.Getenv("AUTH0_DOMAIN")+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			http.Error(w, res.Status, res.StatusCode)
			return
		}

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

		for _, klpd := range data.KLPD {
			for _, satuanKerja := range klpd.SatuanKerja {
				org, err := manager.Auth0API.Organization.ReadByName(klpd.Name + "-" + satuanKerja.Name)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				assignerRoleList, err := manager.Auth0API.Organization.MemberRoles(*org.ID, assigner_uid)
				if err != nil {
					if strings.Contains(err.Error(), "404") {
						http.Error(w, fmt.Sprintf("User has no administrator access in KLPD %s: Satuan Kerja %s", klpd.Name, satuanKerja.Name), http.StatusForbidden)
						return
					}

					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				PPE, Agency := false, false
				for _, role := range assignerRoleList.Roles {
					if *role.Name == "Admin PPE" {
						PPE = true
					} else if *role.Name == "Admin Agency" {
						Agency = true
					}
				}

				for _, role := range satuanKerja.Roles {
					if role == "Admin PPE" || role == "Auditor" {
						http.Error(w, "Action not allowed", http.StatusForbidden)
						return
					} else if role == "Admin Agency" {
						if !PPE {
							http.Error(w, "Action not allowed", http.StatusForbidden)
							return
						}
					} else {
						if !PPE && !Agency {
							http.Error(w, "Action not allowed", http.StatusForbidden)
							return
						}
					}
				}
			}
		}

		// Copy back the original data to request body
		r.Body = rdr2
		next.ServeHTTP(w, r)
	})
}
