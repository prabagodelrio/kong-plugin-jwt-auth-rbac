package = "kong-plugin-jwt-auth-rbac"
version = "0.1.0-1"

supported_platforms = {"linux", "macosx"}

source = {
   url = "git+https://github.com/infonova/kong-plugin-jwt-auth-rbac",
   tag = "v0.4.0",
}

description = {
   summary = "A Kong plugin to authorize access based on a roles claim",
   homepage = "https://github.com/infonova/kong-plugin-jwt-auth-rbac",
   license = "MIT",
}

dependencies = {
   "lua >= 5.4",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-auth-rbac.handler"] = "handler.lua",
    ["kong.plugins.jwt-auth-rbac.schema"] = "schema.lua",
  },
}
