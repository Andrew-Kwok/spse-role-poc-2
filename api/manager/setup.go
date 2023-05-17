package manager

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
)

var Auth0API *management.Management

func ConnectAPI() {
	auth0API, err := management.New(
		os.Getenv("AUTH0_DOMAIN"),
		management.WithStaticToken(os.Getenv("MGMT_ACCESS_TOKEN")),

		// TODO: Connect using CLIENT_ID and CLIENT_SECRET
		// management.WithClientCredentials(os.Getenv("AUTH0_CLIENT_ID"), os.Getenv("AUTH0_CLIENT_SECRET")),
	)
	if err != nil {
		log.Fatal("Error connecting to Auth0 Management API:", err)
	}
	Auth0API = auth0API
}

// Generate organizations and roles in auth0
// Precondition:
// - Auth0API refers to a valid management API
func GenerateOrganizationAndRoles() {
	for ch := 'a'; ch <= 'b'; ch++ {
		for i := 1; i <= 3; i++ {
			KLPD := string(ch)
			satuanKerja := string(ch) + strconv.Itoa(i)
			newOrganization := &management.Organization{
				Name:        auth0.String(KLPD + "-" + satuanKerja),
				DisplayName: auth0.String(fmt.Sprintf("KLPD %s: Satuan Kerja %s", KLPD, satuanKerja)),
			}
			err := Auth0API.Organization.Create(newOrganization)

			if err != nil {
				log.Printf("Error when creating organization %s, err %s", KLPD+"-"+satuanKerja, err)
			}
		}
	}

	available_roles := []string{"Admin PPE", "Admin Agency", "Verifikator", "Helpdesk", "PPK", "KUPBJ", "Anggota Pokmil", "PP", "Auditor"}
	for _, role := range available_roles {
		newRole := &management.Role{
			Name:        auth0.String(role),
			Description: auth0.String("Placeholder Description"),
		}
		err := Auth0API.Role.Create(newRole)
		if err != nil {
			log.Printf("Error when creating role %s, err %s", role, err)
		}
	}
}
