return {
  no_consumer = true,
  fields = {
    roles = {type = "array", default = {}},
    roles_claim_name = {type = "string", default = "roles"},
    msg_error = {type = "string", default = "You can't use these service"},
    policy = {type = "string", default = "any", enum = {"any", "all"}}
  }
}