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
	// manager.GenerateOrganizationAndRoles()
	manager.RoleSetup()

	r := router.New()
	port := os.Getenv("API_PORT")
	log.Printf("Starting up on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
