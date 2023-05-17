package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"spse-role-poc/api/manager"

	"github.com/joho/godotenv"
)

func setup(t *testing.T) {
	err := godotenv.Load()
	if err != nil {
		t.Fatal("Error loading .env file")
	}
	manager.ConnectAPI()
	manager.RoleSetup()
}

// Takes `email`, `password,` and `roles` as input, then tries the CreateUserHandler
// to see if it created a new user as expected
func testCreateHelper(t *testing.T, data map[string]interface{}, expectedStatus int) string {
	server := httptest.NewServer(http.HandlerFunc(manager.CreateUserHandler))
	defer server.Close()

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal JSON data: %v", err)
	}

	req, err := http.NewRequest("POST", server.URL+"/create", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if res.StatusCode != expectedStatus {
		t.Log(string(body))
		t.Fatalf("unexpected status code: got %d, want %d", res.StatusCode, expectedStatus)
	}

	if res.StatusCode == http.StatusCreated {
		var responseData struct {
			Message string `json:"message"`
		}
		err = json.Unmarshal(body, &responseData)
		if err != nil {
			t.Fatalf("Failed to unmarshal JSON data: %v", err)
		}

		// each user_id begins with auth0|<uid>
		// look for the index and extract the uid
		index := strings.Index(responseData.Message, "auth0|")
		return responseData.Message[index:]
	}
	return ""
}

// Takes `user_id`, and `roles` as input, then tries the AddRolesHandler or RewriteRolesHandler
// to see if it updated the roles of the user as expected
func testPatchHelper(t *testing.T, command string, data map[string]interface{}, expectedStatus int) {
	server := httptest.NewServer(http.HandlerFunc(manager.RewriteRolesHandler))
	if command == "rewriteroles" {
		server = httptest.NewServer(http.HandlerFunc(manager.RewriteRolesHandler))
	}

	defer server.Close()

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal JSON data: %v", err)
	}

	req, err := http.NewRequest("POST", server.URL+"/"+command, bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if res.StatusCode != expectedStatus {
		t.Log(string(body), data)
		t.Fatalf("unexpected status code: got %d, want %d", res.StatusCode, expectedStatus)
	}
}

// Check if the roles of user with <uid> in Auth0 has the same roles as expectedRoles
func checkRoles(t *testing.T, uid string, expectedRoles []string) error {
	orgList, err := manager.Auth0API.User.Organizations(uid)
	if err != nil {
		t.Fatal(err)
	}

	actualRoles := make([]string, 0)
	for _, org := range orgList.Organizations {
		roleList, err := manager.Auth0API.Organization.MemberRoles(*org.ID, uid)
		if err != nil {
			t.Fatal(err)
		}

		for _, role := range roleList.Roles {
			actualRoles = append(actualRoles, *org.Name+"-"+*role.Name)
		}
	}
	sort.Strings(actualRoles)
	sort.Strings(expectedRoles)

	if len(actualRoles) != len(expectedRoles) {
		t.Fatal("Expected ", expectedRoles, ". Got ", actualRoles)
	}

	for i := 0; i < len(expectedRoles); i++ {
		if actualRoles[i] != expectedRoles[i] {
			t.Fatal("Expected ", expectedRoles, ". Got ", actualRoles)
		}
	}
	return nil
}

func TestCreateEmptyRole(t *testing.T) {
	setup(t)
	data := map[string]interface{}{
		"email":    "__test100@example.com",
		"password": "Test123!",
	}
	uid := testCreateHelper(t, data, http.StatusCreated)
	defer manager.Auth0API.User.Delete(uid)
	checkRoles(t, uid, []string{})
}

func TestCreateOnlyPengelola(t *testing.T) {
	setup(t)

	queryRoles := []map[string]interface{}{
		{
			"name": "a",
			"satuan-kerja": []map[string]interface{}{
				{
					"name":  "a1",
					"roles": []string{"Admin PPE", "Admin Agency"},
				},
			},
		},
	}
	expectedRoles := []string{"a-a1-Admin PPE", "a-a1-Admin Agency"}
	data := map[string]interface{}{
		"email":    "__test100@example.com",
		"password": "Test123!",
		"klpd":     queryRoles,
	}
	uid := testCreateHelper(t, data, http.StatusCreated)
	defer manager.Auth0API.User.Delete(uid)
	checkRoles(t, uid, expectedRoles)
}

func TestCreateOnlyPengadaan(t *testing.T) {
	setup(t)
	queryRoles := []map[string]interface{}{
		{
			"name": "a",
			"satuan-kerja": []map[string]interface{}{
				{
					"name":  "a2",
					"roles": []string{"PPK"},
				},
			},
		},
		{
			"name": "b",
			"satuan-kerja": []map[string]interface{}{
				{
					"name":  "b2",
					"roles": []string{"KUPBJ", "Anggota Pokmil"},
				},
				{
					"name":  "b3",
					"roles": []string{"PP", "KUPBJ", "Anggota Pokmil"},
				},
			},
		},
	}

	expectedRoles := []string{"a-a2-PPK", "b-b2-KUPBJ", "b-b2-Anggota Pokmil", "b-b3-PP", "b-b3-KUPBJ", "b-b3-Anggota Pokmil"}
	data := map[string]interface{}{
		"email":    "__test100@example.com",
		"password": "Test123!",
		"klpd":     queryRoles,
	}
	uid := testCreateHelper(t, data, http.StatusCreated)
	defer manager.Auth0API.User.Delete(uid)
	checkRoles(t, uid, expectedRoles)
}

func TestCreateOnlyAuditor(t *testing.T) {
	setup(t)
	queryRoles := []map[string]interface{}{
		{
			"name": "b",
			"satuan-kerja": []map[string]interface{}{
				{
					"name":  "b1",
					"roles": []string{"Auditor"},
				},
				{
					"name":  "b2",
					"roles": []string{"Auditor"},
				},
				{
					"name":  "b3",
					"roles": []string{"Auditor"},
				},
			},
		},
	}
	expectedRoles := []string{"b-b1-Auditor", "b-b2-Auditor", "b-b3-Auditor"}
	data := map[string]interface{}{
		"email":    "__test100@example.com",
		"password": "Test123!",
		"klpd":     queryRoles,
	}
	uid := testCreateHelper(t, data, http.StatusCreated)
	defer manager.Auth0API.User.Delete(uid)
	checkRoles(t, uid, expectedRoles)
}

func TestCreatePP_PPK(t *testing.T) {
	setup(t)
	data := map[string]interface{}{
		"email":    "__test100@example.com",
		"password": "Test123!",
		"klpd": []map[string]interface{}{
			{
				"name": "a",
				"satuan-kerja": []map[string]interface{}{
					{
						"name":  "a1",
						"roles": []string{"PP"},
					},
					{
						"name":  "a2",
						"roles": []string{"PPK"},
					},
				},
			},
		},
	}
	testCreateHelper(t, data, http.StatusBadRequest)
}

func TestCreateCrossFunction(t *testing.T) {
	setup(t)
	data := map[string]interface{}{
		"email":    "__test100@example.com",
		"password": "Test123!",
		"klpd": []map[string]interface{}{
			{
				"name": "b",
				"satuan-kerja": []map[string]interface{}{
					{
						"name":  "b2",
						"roles": []string{"PPK", "KUPBJ", "Admin PPE"},
					},
				},
			},
		},
	}
	testCreateHelper(t, data, http.StatusBadRequest)
}

func TestCreateCrossFunction2(t *testing.T) {
	setup(t)
	data := map[string]interface{}{
		"email":    "__test100@example.com",
		"password": "Test123!",
		"klpd": []map[string]interface{}{
			{
				"name": "a",
				"satuan-kerja": []map[string]interface{}{
					{
						"name":  "a1",
						"roles": []string{"Admin PPE"},
					},
				},
			},
			{
				"name": "b",
				"satuan-kerja": []map[string]interface{}{
					{
						"name":  "b3",
						"roles": []string{"Helpdesk", "Auditor"},
					},
				},
			},
		},
	}
	testCreateHelper(t, data, http.StatusBadRequest)
}

// func TestAddRoles(t *testing.T) {
// 	setup(t)
// 	data := map[string]interface{}{
// 		"email":    "__test100@example.com",
// 		"password": "Test123!",
// 	}
// 	uid := testCreateHelper(t, data, http.StatusCreated)
// 	defer manager.Auth0API.User.Delete(uid)

// 	expectedRoles := []string{"A:A1:Admin PPE", "A:A1:Admin Agency", "A:A1:Verifikator", "A:A1:Helpdesk"}
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": []string{"A:A1:Admin PPE", "A:A1:Admin Agency", "A:A1:Verifikator", "A:A1:Helpdesk"},
// 	}
// 	testPatchHelper(t, "addroles", data, http.StatusOK)
// 	checkRoles(t, uid, expectedRoles)

// 	// No roles should be added
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": []string{"A1:Admin PP"},
// 	}
// 	testPatchHelper(t, "addroles", data, http.StatusBadRequest)
// 	checkRoles(t, uid, expectedRoles)

// 	// B:A1:PP should be allowed to be added
// 	expectedRoles = append(expectedRoles, "B:A1:PP")
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": []string{"B:A1:PP"},
// 	}
// 	testPatchHelper(t, "addroles", data, http.StatusOK)
// 	checkRoles(t, uid, expectedRoles)

// 	// B:A1:KUPBJ should be allowed to be added
// 	expectedRoles = append(expectedRoles, "B:A1:KUPBJ")
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": []string{"B:A1:KUPBJ"},
// 	}
// 	testPatchHelper(t, "addroles", data, http.StatusOK)
// 	checkRoles(t, uid, expectedRoles)

// 	// B:A2:PPK should not be allowed to be added since B:A1:PP exists
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": []string{"B:A2:PPK"},
// 	}
// 	testPatchHelper(t, "addroles", data, http.StatusBadRequest)
// 	checkRoles(t, uid, expectedRoles)

// 	// B:A3:Auditor should not be allowed to be added since it has functions in Pelaku Pengadaan LPSE in B
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": []string{"B:A3:Auditor"},
// 	}
// 	testPatchHelper(t, "addroles", data, http.StatusBadRequest)
// 	checkRoles(t, uid, expectedRoles)
// }

// func TestRewriteRoles(t *testing.T) {
// 	setup(t)
// 	data := map[string]interface{}{
// 		"email":    "__test100@example.com",
// 		"password": "Test123!",
// 	}
// 	uid := testCreateHelper(t, data, http.StatusCreated)
// 	defer manager.Auth0API.User.Delete(uid)

// 	queryRoles := []string{"A:A1:Admin PPE", "A:A1:Admin Agency", "A:A1:Verifikator", "A:A1:Helpdesk"}
// 	expectedRoles := queryRoles

// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": queryRoles,
// 	}
// 	testPatchHelper(t, "rewriteroles", data, http.StatusOK)
// 	checkRoles(t, uid, expectedRoles)

// 	// Action should not be allowed since PP and PPK both exists under the same KLPD
// 	queryRoles = []string{"B:A1:PPK", "B:A1:KUPBJ", "B:A1:Anggota Pokmil", "B:A3:PP"}
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": queryRoles,
// 	}
// 	testPatchHelper(t, "rewriteroles", data, http.StatusBadRequest)
// 	checkRoles(t, uid, expectedRoles)

// 	// Action should be allowed since PP and PPK exists under the differnt KLPD
// 	queryRoles = []string{"A:A1:PPK", "B:A1:KUPBJ", "B:A1:Anggota Pokmil", "B:A3:PP"}
// 	expectedRoles = queryRoles
// 	data = map[string]interface{}{
// 		"id":    uid,
// 		"roles": queryRoles,
// 	}
// 	testPatchHelper(t, "rewriteroles", data, http.StatusOK)
// 	checkRoles(t, uid, expectedRoles)
// }

// Extra Utility
func deleteUser(email string) error {
	userList, err := manager.Auth0API.User.List()
	if err != nil {
		return err
	}

	for _, user := range userList.Users {
		if *user.Email == email {
			manager.Auth0API.User.Delete(*user.ID)
			return nil
		}
	}
	return nil
}

func deleteAllTest() error {
	userList, err := manager.Auth0API.User.List()
	if err != nil {
		return err
	}

	uid_to_be_deleted := make([]string, 0)
	for _, user := range userList.Users {
		if strings.Contains(*user.Email, "test") {
			uid_to_be_deleted = append(uid_to_be_deleted, *user.ID)
		}
	}

	for _, uid := range uid_to_be_deleted {
		manager.Auth0API.User.Delete(uid)
	}
	return nil
}
