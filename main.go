package main

import (
	"log"
	"net/http"
	"os"

	"spse-role-poc/api/manager"
	"spse-role-poc/api/router"

	// "github.com/auth0/go-auth0"
	// "github.com/auth0/go-auth0/management"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	manager.ConnectAPI()
	manager.RoleSetup()

	// // generate roles in auth0;
	// available_roles := []string{"Admin PPE", "Admin Agency", "Verifikator", "Helpdesk", "PPK", "KUPBJ", "Anggota Pokmil", "PP", "Auditor"}
	// for ch := 'A'; ch <= 'B'; ch++ {
	// 	for i := 1; i <= 3; i++ {
	// 		for _, role := range available_roles {
	// 			KLPD := string(ch)
	// 			satuanKerja := "A" + strconv.Itoa(i)
	// 			roleFunction := role
	// 			newRole := &management.Role{
	// 				Name:        auth0.String(KLPD + ":" + satuanKerja + ":" + roleFunction),
	// 				Description: auth0.String("Placeholder Description"),
	// 			}
	// 			manager.Auth0API.Role.Create(newRole)
	// 		}
	// 	}
	// }
	// return

	r := router.New()
	port := os.Getenv("API_PORT")
	log.Printf("Starting up on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
