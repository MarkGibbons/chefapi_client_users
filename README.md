# chefapi_client_users

This code provides a go client interface to the chefapi to interact with users.
Running this code provides a simpler API than the native chef REST API for use by web applications.
See the chefapi_demo_server repository to see how this code was installed and started.

## Front End Endpoints used by web applications
-----------

### DELETE /users
=================
### GET /users
==============
### POST /users
===============

### GET /orgadmins
=================

### GET /orgusers
=================

#### Request
Filter values may restrict the returned information to a specific owner of the 
users and to a specific organization.  If not set users for all users and/or all
organizations will be returned.

The request can specify filter values in a json body.
````json
{
  "user": "username",
  "organization" "orgname"
}
````


#### Return
The body returned looks like this:
````json
{
  "organization": "orgname",
  "admins": [
     "user1",
     "user2"
   ],
  "users": [
     "user1",
     "user2"
   ]
}
````

Values
200 - List returned
400 - Invalid request was made
403 - Unauthorized request was made

### GET /orgusers/ORG/users/USER
================================

#### Request


#### Return
The body returned looks like this:
````json
{
  "name": "user_name",
  "chef_environment": "_default",
  "run_list": [
    "recipe[recipe_name]"
  ]
  "json_class": "Chef::Node",
  "chef_type": "user",
  "automatic": { ... },
  "normal": { "tags": [ ] },
  "default": { },
  "override": { }
}
````

Values
200 - Node data returned
400 - Invalid request was made
403 - Unauthorized request was made

### PUT /orgusers/ORG/users/USER
================================

#### Request
The request body looks like this:
````json
{
  "name": "user_name",
  "chef_environment": "_default",
  "run_list": [
    "recipe[recipe_name]"
  ]
  "json_class": "Chef::Node",
  "chef_type": "user",
  "automatic": { ... },
  "normal": { "tags": [ ] },
  "default": { },
  "override": { }
}
````

#### Return
  No body is returned
````
Values
200 - Node data returned
400 - Invalid request was made
403 - Unauthorized request was made

## Back End Chef Infra Server Endpoints used
-----------

### DELETE /Users
### POST /Users
### GET /Users
### POST /Associations
### GET /Groups/NAME
