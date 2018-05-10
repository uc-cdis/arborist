package cases

import (
	. "github.com/uc-cdis/arborist/arborist"
)

func makeTestRole(
	ID string,
	tags []string,
	permissions []*Permission,
	subroles []*Role,
	parent *Role,
) *Role {
	role, err := NewRole(ID)
	if err != nil {
		panic(err)
	}
	role.Parent = parent
	for _, tag := range tags {
		role.Tags[tag] = struct{}{}
	}
	for _, permission := range permissions {
		role.Permissions[permission] = struct{}{}
	}
	for _, subrole := range subroles {
		role.Subroles[subrole] = struct{}{}
	}
	return &role
}

// Define a couple example resources.
var stove Resource = NewResource("kitchen", "stove")
var cookbook Resource = NewResource("kitchen", "cookbook")
var pantry Resource = NewResource("kitchen", "pantry")

// Define some permissions for using the resources.
var permissionStoveCook Permission = Permission{
	ID: "use_stove",
	Action: Action{
		Service:  "kitchen",
		Resource: &stove,
		Method:   "cook",
	},
	Constraints: NewEmptyConstraints(),
}
var permissionCookbookRead Permission = Permission{
	ID: "cookbook_read",
	Action: Action{
		Service:  "kitchen",
		Resource: &cookbook,
		Method:   "read",
	},
	Constraints: NewEmptyConstraints(),
}
var permissionCookbookAll Permission = Permission{
	ID: "cookbook_all",
	Action: Action{
		Service:  "kitchen",
		Resource: &cookbook,
		Method:   "*",
	},
	Constraints: NewEmptyConstraints(),
}
var permissionpantry = Permission{
	ID: "pantry",
	Action: Action{
		Service:  "kitchen",
		Resource: &pantry,
		Method:   "*",
	},
	Constraints: NewEmptyConstraints(),
}

var RoleChefDePartie *Role = makeTestRole(
	"chef_de_partie",
	[]string{},
	[]*Permission{&permissionpantry, &permissionCookbookRead},
	[]*Role{},
	nil,
)

const RoleChefDePartieJSON string = `
{
	"id": "chef_de_partie",
	"tags": [],
	"permissions": [
		{
			"id": "kitchen_ingredients",
			"action": {
				"service": "kitchen",
				"resource": "pantry",
				"method": "*"
			},
			"constraints": {}
		},
		{
			"id": "use_stove",
			"action": {
				"service": "kitchen",
				"resource": "stove",
				"method": "cook"
			}
		},
		{
			"id": "read_cookbook",
			"action": {
				"service": "cookbook",
				"resource": "recipe",
				"method": "read"
			}
		}
	],
	"subroles": []
}
`

var RoleSousChef *Role = makeTestRole(
	"sous_chef",
	[]string{},
	[]*Permission{},
	[]*Role{RoleChefDePartie},
	nil,
)

var RoleChefDeCuisine *Role = makeTestRole(
	"chef_de_cuisine",
	[]string{},
	[]*Permission{&permissionCookbookAll},
	[]*Role{RoleSousChef},
	nil,
)

const RoleChefDeCuisineJSON string = `
{
	"id": "chef_de_cuisine",
	"tags": ["chef", "food"],
	"permissions": [
		{
			"id": "define_recipe",
			"action": {
				"service": "cookbook",
				"resource": "recipe",
				"method": "*"
			},
			"constraints": {}
		}
	],
	"subroles": [
		{
			"id": "sous_chef",
			"tags": [],
			"permissions": [
				{
					"id": "direct_chefs",
					"action": {
						"service": "",
						"resource": "",
						"method": ""
					},
					"constraints": {}
				}
			],
			"subroles": [
				{
					"id": "chef_de_partie",
					"permissions": [
						{
							"id": "kitchen_ingredients",
							"action": {
								"service": "kitchen",
								"resource": "pantry",
								"method": "*"
							},
							"constraints": {}
						},
						{
							"id": "use_stove",
							"action": {
								"service": "kitchen",
								"resource": "stove",
								"method": "cook"
							}
						},
						{
							"id": "read_cookbook",
							"action": {
								"service": "cookbook",
								"resource": "recipe",
								"method": "read"
							}
						}
					]
				}
			]
		}
	]
}
`
