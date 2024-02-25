local plugin_name = "jwt-auth-rbac"
local package_name = "kong-plugin-" .. plugin_name
local package_version = "0.4.0"
local rockspec_revision = "1"

local github_account_name = "infonova"
local github_repo_name = package_name
local git_checkout = package_version == "dev" and "master" or package_version

package = package_name
version = package_version .. "-" .. rockspec_revision
supported_platforms = {"linux", "macosx"}

source = {
   url = "git+https://github.com/"..github_account_name.."/"..github_repo_name..".git",
   branch = git_checkout,
}

description = {
   summary = "A Kong plugin to authorize access based on a roles claim",
   homepage = "https://"..github_account_name..".github.io/"..github_repo_name,
   license = "MIT",
}

dependencies = {
   "lua ~> 5",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-auth-rbac.handler"] = "handler.lua",
    ["kong.plugins.jwt-auth-rbac.schema"]  = "schema.lua",
  },
}
