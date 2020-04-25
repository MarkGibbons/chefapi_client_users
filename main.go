package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/MarkGibbons/chefapi_client"
	"github.com/MarkGibbons/chefapi_lib"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chef/chef"
	"github.com/gorilla/mux"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
)

type restInfo struct {
	AuthUrl string
	Cert    string
	Key     string
	Port    string
}

type UserFilters struct {
	User         string `json:"user,omitempty"`
	Organization string `json:"organization,omitempty"`
}

type OrgUsers []UserList

type UserList struct {
	Organization string   `json:"organization"`
	Users        []string `json:"users"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var flags restInfo

var jwtKey = []byte("my_secret_key") // TODO: Parameter for production

func main() {
	flagInit()
	// users - global chef users 
	// DELETE - Delete a user
	// GET - list of all global users
	// POST - Add a chef user with body
	// orgusers - all organizations and users in those organizations
	// GET - list of all users in all orgs
	// orgusers/{org}/users/{user}
	// POST - Add the user to the organization 

	r := mux.NewRouter()
	r.HandleFunc("/users", globalUsers)
	r.HandleFunc("/orgadmins", getOrgAdmins)
	r.HandleFunc("/orgusers", getOrgUsers)
	r.HandleFunc("/orgusers/{org}/users/{user}", addOrgUser)
	l, err := net.Listen("tcp4", ":"+flags.Port)
	if  err  != nil {
		panic(err.Error())
	}
	log.Fatal(http.ServeTLS(l, r, flags.Cert, flags.Key))
	return
}

func globalUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Global user request\n")
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	err := cleanInput(vars)
	if err != nil {
		inputerror(&w)
		return
	}

	// Get the filters from parameters
	var filters UserFilters
	userparm, ok := r.URL.Query()["user"]
	if ok {
		filters.User = userparm[0]
	}

	// Verify a logged in user made the request
	username, code := loggedIn(r)
	if code != -1 {
		fmt.Printf("Can't verify the user status: %+v\n", code)
		w.WriteHeader(code)
		return
	}

	fmt.Printf("Route by method %+v\n",r.Method)
	switch r.Method {
	case "DELETE":
		fmt.Printf("Delete user\n")
	        client := chefapi_client.Client()
		err := client.Users.Delete(username)
		fmt.Printf("Delete %+v Err %+v\n", username, err)
		if err != nil {
		        w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	case "GET":
		// Extract the user list
		users, err := allUsers(filters)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		//  Handle the results and return the json body
		usersJSON, err := json.Marshal(users)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Printf("Get all global users %+v\n", string(usersJSON))
		w.WriteHeader(http.StatusOK)
		w.Write(usersJSON)
		return
	case "POST":
		fmt.Printf("Create user\n")
	        client := chefapi_client.Client()
		user := chef.User{}
		err = json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
		        fmt.Printf("Body error user %+v Err %+v\n", user, err)
		        w.WriteHeader(http.StatusBadRequest)
			return
		}

                // verify the username = the authenticated name
		if username != user.UserName {
		        fmt.Printf("Not authorized to add other users %+v %+v\n", username, user.UserName)
		        w.WriteHeader(http.StatusForbidden)
			return
		}

		userresult, err := client.Users.Create(user)
		fmt.Printf("Create user %+v Err %+v\n", user, err)
		if err != nil {
		        w.WriteHeader(http.StatusBadRequest)
			return
		}
		userJSON, err := json.Marshal(userresult)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(userJSON)
		return
	}

	return
}

func getOrgAdmins(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	err := cleanInput(vars)
	if err != nil {
		inputerror(&w)
		return
	}

	// Get the filters from parameters
	var filters UserFilters
	userparm, ok := r.URL.Query()["user"]
	if ok {
		filters.User = userparm[0]
	}
	orgparm, ok := r.URL.Query()["organization"]
	if ok {
		filters.Organization = orgparm[0]
	}

	// Verify a logged in user made the request
	_, code := loggedIn(r)
	if code != -1 {
		fmt.Printf("Can't verify the user status: %+v\n", code)
		w.WriteHeader(code)
		return
	}

	// Get a list of organizations to search for this request
	fmt.Printf("Filters : %+v", filters)
	var orgList []string
	if filters.Organization == "" {
		orgList, err = allOrgs()
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	} else {
		orgList = append(orgList, filters.Organization)
	}

	// Extract the user list
	orgAdmins, err := allOrgAdmins(orgList, filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//  Handle the results and return the json body
	usersJSON, err := json.Marshal(orgAdmins)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("Org admins %+v Err %+v\n", orgAdmins, err)
	w.WriteHeader(http.StatusOK)
	w.Write(usersJSON)
	return
}

func getOrgUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	err := cleanInput(vars)
	if err != nil {
		inputerror(&w)
		return
	}

	// Get the filters from parameters
	var filters UserFilters
	userparm, ok := r.URL.Query()["user"]
	if ok {
		filters.User = userparm[0]
	}
	orgparm, ok := r.URL.Query()["organization"]
	if ok {
		filters.Organization = orgparm[0]
	}

	// Verify a logged in user made the request
	_, code := loggedIn(r)
	if code != -1 {
		fmt.Printf("Can't verify the user status: %+v\n", code)
		w.WriteHeader(code)
		return
	}

	// Get a list of organizations to search for this request
	fmt.Printf("Filters : %+v", filters)
	var orgList []string
	if filters.Organization == "" {
		orgList, err = allOrgs()
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	} else {
		orgList = append(orgList, filters.Organization)
	}

	// Extract the user list
	orgUsers, err := allOrgUsers(orgList, filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//  Handle the results and return the json body
	usersJSON, err := json.Marshal(orgUsers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Printf("Org users %+v Err %+v\n", orgUsers, err)
	w.WriteHeader(http.StatusOK)
	w.Write(usersJSON)
	return
}

func addOrgUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	err := cleanInput(vars)
	if err != nil {
		inputerror(&w)
		return
	}

	switch r.Method {
	case "POST":
		// Verify a logged in user made the request
		username, code := loggedIn(r)
		if code != -1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// the authenicated user can only add themself
		user := vars["user"]
		if user != username {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		// Verify the user is allowed to join this organizations
		org := vars["org"]
		userauth, err := userAllowed(username, org)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !userauth {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		err = addAssociation(org, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	default:
	}
	return
}

func allUsers(filters UserFilters) (users []string, err error) {
	client := chefapi_client.Client()
	users, err = listUsers(client, filters)
	return
}

func allOrgUsers(orgs []string, filters UserFilters) (orgusers OrgUsers, err error) {
	for _, org := range orgs {
		userlist := UserList{}
		userlist.Organization = org
		client := chefapi_client.OrgClient(org)
		usernames, err := listOrgUsers(client, filters)
		if err != nil {
			fmt.Printf("Error listing org users for %+v Err %+v Names %+v\n", org, err, usernames)
		        orgusers = append(orgusers, userlist)
			continue
		}
		userlist.Users = usernames
		orgusers = append(orgusers, userlist)
	}
	return
}

func allOrgAdmins(orgs []string, filters UserFilters) (orgusers OrgUsers, err error) {
	for _, org := range orgs {
		userlist := UserList{}
		userlist.Organization = org
		client := chefapi_client.OrgClient(org)
		usernames, err := listOrgAdmins(client, filters)
		if err != nil {
			fmt.Printf("Error listing org admins for %+v Err %+v Names %+v\n", org, err, usernames)
		        orgusers = append(orgusers, userlist)
			continue
		}
		userlist.Users = usernames
		orgusers = append(orgusers, userlist)
	}
	return
}

func postUser(organization string, user chef.User) (err error) {
	client := chefapi_client.OrgClient(organization)
	_, err = client.Users.Create(user)
	return
}

func addAssociation(organization string, user string) (err error) {
	adduser := chef.AddNow{ Username: user }
	client := chefapi_client.OrgClient(organization)
	err = client.Associations.Add(adduser)
	return
}

func listUsers(client *chef.Client, filters UserFilters) (userNames []string, err error) {
	userList, err := client.Users.List()
	if err != nil {
		fmt.Printf("User list failed %+v\n", err)
		return
	}
	userNames = make([]string, 0, len(userList))
	nameMatcher, err := regexp.Compile(filters.User)
	if err != nil {
		err = errors.New("Invalid regular expression for the user name filter")
		return
	}
	for user, _ := range userList {
		// apply the name filter
		if !nameMatcher.Match([]byte(user)) {
			continue
		}
		userNames = append(userNames, user)
	}
	return userNames, err
}

func listOrgUsers(client *chef.Client, filters UserFilters) (userNames []string, err error) {
	fmt.Printf("listOrgUsers\n")
	userList, err := client.Associations.List()
	fmt.Printf("Dump org userList %+v Err %+v\n", userList, err)
	if err != nil {
		fmt.Printf("Association list failed %+v\n", err)
		return
	}
	// Make a common routine for user filter pass in the right user list
	userNames = make([]string, 0, len(userList))
	nameMatcher, err := regexp.Compile(filters.User)
	if err != nil {
		err = errors.New("Invalid regular expression for the user name filter")
		return
	}
	for _, userentry := range userList {
		// apply the name filter
		user := userentry.User.Username
		if !nameMatcher.Match([]byte(user)) {
			continue
		}
		userNames = append(userNames, user)
	}
	return userNames, err
}

func listOrgAdmins(client *chef.Client, filters UserFilters) (userNames []string, err error) {
	groupOut, err := client.Groups.Get("admins")
	if err != nil {
		fmt.Printf("Group list failed %+v\n", err)
		return
	}
	userList := groupOut.Users
	fmt.Printf("Found users in admins group %+v\n", userList)
	fmt.Printf("Admins group %+v\n", groupOut)
	// Make a common routine for user filter pass in the right user list
	userNames = make([]string, 0, len(userList))
	nameMatcher, err := regexp.Compile(filters.User)
	if err != nil {
		err = errors.New("Invalid regular expression for the user name filter")
		return
	}
	for _, user := range userList {
		// apply the name filter
		if !nameMatcher.Match([]byte(user)) {
			continue
		}
		userNames = append(userNames, user)
	}
	return userNames, err
}

func allOrgs() (orgNames []string, err error) {
	client := chefapi_client.Client()
	orgList, err := client.Organizations.List()
	orgNames = make([]string, 0, len(orgList))
	for k := range orgList {
		orgNames = append(orgNames, k)
	}
	return
}

func cleanInput(vars map[string]string) (err error) {
	for _, value := range vars {
		matched, _ := regexp.MatchString("^[[:word:]]+$", value)
		if !matched {
			err = errors.New("Invalid value in the URI")
			break
		}
	}
	return
}

func flagInit() {
	restcert := flag.String("restcert", "", "Rest Certificate File")
	restkey := flag.String("restkey", "", "Rest Key File")
	restport := flag.String("restport", "8111", "Rest interface https port")
	authurl := flag.String("authurl", "", "User authorization service url")
	flag.Parse()
	flags.AuthUrl = *authurl
	flags.Cert = *restcert
	flags.Key = *restkey
	flags.Port = *restport
	fmt.Printf("Flags used %+v\n", flags)
	return
}

func inputerror(w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusBadRequest)
	(*w).Write([]byte(`{"message":"Bad url input value"}`))
}

func userAllowed(user string, org string) (authorized bool, err error) {
	authorized = false
	authurl := flags.AuthUrl + "/auth/" + user + "/org/" + org
	resp, err := http.Get(authurl)
	if err != nil {
		return
	}
	var auth chefapi_lib.Auth
	err = json.NewDecoder(resp.Body).Decode(&auth)
	if err != nil {
		return
	}
	authorized = auth.Auth
	return
}

// loggedIn verifies the JWT and extracts the user name
func loggedIn(r *http.Request) (user string, code int) {
	// Common routine
	code = -1
	reqToken := r.Header.Get("Authorization")
	fmt.Printf("REQTOKEN %+v\n", reqToken)
	splitToken := strings.Split(reqToken, "Bearer")
	// Verify index before using
	if len(splitToken) != 2 {
		code = http.StatusUnauthorized
		return
	}
	tknStr := strings.TrimSpace(splitToken[1])
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			code = http.StatusUnauthorized
			return
		}
		code = http.StatusBadRequest
		return
	}
	if !tkn.Valid {
		code = http.StatusUnauthorized
		return
	}
	user = claims.Username
	return
}
