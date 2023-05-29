# spse-role-poc

Fill `MGMT_ACCESS_TOKEN=` in `.env`. This can be obtained from Auth0 > APIs > Auth0 Management API > API Explorer.

Start the API by calling `go run main.go`. This will starts the API
To create a user, send a `GET` request to `localhost:3000/create` with request body
```
{
    "email": "{user_email}",
    "password": "{user_password}",
    "klpd": [
        {
            "name": "{KLPD NAME}",
            "satuan-kerja": [
                {
                    "name": "{SATUAN KERJA NAME}",
                    "roles": [{ROLE 1 NAME, ROLE 2 NAME, ...}]
                }
            ]
        }
    ]
}
```

Available KLPD: `{"a", "b"}`
Available _Satuan Kerja_: `{"a1", "a2", "a3", "b1", "b2", "b3"}`
Available roles: `{"Admin PPE", "Admin Agency", "Verifikator", "Helpdesk", "PPK", "KUPBJ", "Anggota Pokmil", "PP", "Auditor"}` 


send a `PATCH` request to `localhost:3000/addroles`, `localhost:3000/deleteroles` with request body
```
{
    "id": "{user_id}",
    "klpd": [
        {
            "name": "{KLPD NAME}",
            "satuan-kerja": [
                {
                    "name": "{SATUAN KERJA NAME}",
                    "roles": [{ROLE 1 NAME, ROLE 2 NAME, ...}]
                }
            ]
        }
    ]
}
```
to add roles and to delete roles for user with {user_id} respectively.


To access the token-protected API, set the header `TOKEN` with access token obtained from user login
Then, access `localhost:3000/create-protected`, `localhost:3000/addroles-protected`, `localhost:3000/deleteroles-protected` with the same request type and request body as the endpoint above.
