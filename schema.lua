return {
  no_consumer = true,
  fields = {
    roles = {type = "array", default = {}},
    roles_claim_name = {type = "string", default = "roles"},
    msg_error_any = {type = "string", default = "To be able to use this service you must have at least one of the roles configured"},
    msg_error_all = {type = "string", default = "In order to use this service you must match all the roles configured with the associated ones in the JWT token"},
    msg_error_not_roles_claimed = {type = "string", default = "The claim roles are not informed in the JWT token"},
    policy = {type = "string", default = "any", enum = {"any", "all"}}
  }
}