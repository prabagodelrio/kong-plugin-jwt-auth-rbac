
<img src="jwt-auth.png" width="100">


# kong-plugin-jwt-auth-rbac
Kong plugin that performs authorization based on custom role claim in JWT

Based on the project of bjwschaap https://github.com/bjwschaap/kong-plugin-jwt-auth

## How to use
This plugin is typically used on routes to authorize access to a specific
route by checking the roles claimed in the JWT.

This plugin is designed to work alongside the standard JWT plugin provided
by Kong. The default Kong JWT plugin will validate the JWT and authenticate
the consumer. This plugin will use the validated token from the Nginx context
and check a custom roles claim in the JWT to contain at least one of the
roles given in the plugin configuration.

### Configuration parameters
| Parameter        | Type   | Optional | Default | Description |
| ---------------- | ------ | -------- | ------- | ----------- |
| roles_claim_name | string | X        | `roles` | Name of the claim/attribute in the JWT that contains the roles to check |
| roles            | array  | -        |         | List of 1 or more roles that are allowed to use the resource (route, service, etc) |
| msg error        | string | X        | `You cannot consume this service` | Customize the error message |
| policy           | string | X        | `any`   | Determines if at least one, or all roles should match. One of: `any` or `all` |

## Example: enabling the plugin on a route
Configure this plugin on a [route](https://docs.konghq.com/latest/admin-api/#Route-object)
with:

```shell
$ curl -X POST http://kong:8001/routes/{route_id}/plugins \
    --data "name=kong-plugin-jwt-auth-rbac" \
    --data "conf.roles_claim_name=Groups" \
    --data "conf.roles=role1,role2,role3" \
    --data "conf.msg_error=You do not have the necessary role to use this service" \
    --data "conf.policy=all
```
## JWT roles claim
The roles claim in the JWT can be either an array or a (optionally comma-separated) string.

### use cases 1
Multiple roles in a claim called `roles` as a single comma-separated string:
```json
{
    "iss": "rVV0Atsoj7QwSX803D4sbBvFRu2EoTLo",
    "iat": 1539775565,
    "exp": 1571311565,
    "aud": "www.example.com",
    "sub": "jrocket@example.com",
    "roles": "A,B,C,D"
}
```
### use cases 2
Single role in a claim called `perm` as a single simple string:
```json
{
    "iss": "rVV0Atsoj7QwSX803D4sbBvFRu2EoTLo",
    "iat": 1539775565,
    "exp": 1571311565,
    "aud": "www.acme.com",
    "sub": "user1@acme.com",
    "perm": "write"
}
```
### use cases 3
Multiple roles in a claim called `roles` as an array of strings:
```json
{
    "iss": "rVV0Atsoj7QwSX803D4sbBvFRu2EoTLo",
    "iat": 1539775565,
    "exp": 1571311565,
    "aud": "www.acme.com",
    "sub": "user2@acme.com",
    "roles": [
        "Editor",
        "Viewer",
        "Admin"
    ]
}
```
