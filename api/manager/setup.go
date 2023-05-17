package manager

import (
	"log"
	"os"

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
