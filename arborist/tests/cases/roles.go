package cases

const EXAMPLE_ROLE string = `
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
								"resource": "cupboards",
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
