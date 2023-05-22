package manager

import (
	"github.com/auth0/go-auth0/management"
)

// User Information
//
// A role must follows the following json structure:
//
//	{
//		"klpd": [
//			{
//				"name": "{KLPD NAME}",
//				"satuan-kerja": [
//					{
//						"name": "{SATUAN KERJA NAME}",
//						"roles": [{ROLE 1 NAME, ROLE 2 NAME, ...}]
//					}
//				]
//			}
//		]
//	}
type UserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	KLPD     []struct {
		Name        string `json:"name"`
		SatuanKerja []struct {
			Name  string   `json:"name"`
			Roles []string `json:"roles"`
		} `json:"satuan-kerja"`
	} `json:"klpd"`
	SuperAdmin bool `json:"superadmin"`
}

// struct to store a list of error message
type ErrorMessage struct {
	Errors []string `json:"errors"`
}

// Auth0 Go-SDK API
var Auth0API *management.Management
