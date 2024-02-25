local constants = require "kong.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"

local policy_ALL = 'all'
local policy_ANY = 'any'

local JWTAuthHandler = {
    VERSION = "0.4.0",
    PRIORITY = 950
}

--- Filter a table
-- @param filterFnc (function) filter function
-- @return (table) the filtered table 
function table:filter(filterFnc)
    local result = {}

    for k, v in ipairs(self) do
        if filterFnc(v, k, self) then
            table.insert(result, v)
        end
    end

    return result
end

--- Get index of a value at a table.
-- @param any value
-- @return any
function table:find(value)
    for k, v in ipairs(self) do
        if v == value then
            return k
        end
    end
end

--- checks wheter all given roles are also present in the claimed roles
-- @param roles_to_check (array) an array of role names
-- @param claimed_roles (table) list of roles claimed in JWT
-- @return (boolean) true if all given roles are also in the claimed roles
local function all_roles_in_roles_claim(roles_to_check, claimed_roles)
    local result = false
    local diff

    diff = table.filter(roles_to_check, function(value)
        return not table.find(claimed_roles, value)
    end)

    if #diff == 0 then
        result = true
    end

    return result
end

--- checks whether a claimed role is part of a given list of roles.
-- @param roles_to_check (array) an array of role names.
-- @param claimed_roles (table) list of roles claimed in JWT
-- @return (boolean) whether a claimed role is part of any of the given roles.
local function role_in_roles_claim(roles_to_check, claimed_roles)
    local result = false
    for _, role_to_check in ipairs(roles_to_check) do
        for _, role in ipairs(claimed_roles) do
            if role == role_to_check then
                result = true
                break
            end
        end
        if result then
            break
        end
    end

    return result
end

--- split a string into substrings by reparator
-- @param str (string) the string to be splitted
-- @param sep (string) single character string (!) to separate on
-- @return (table) list of separated parts
local function split(str, sep)
    local ret = {}
    local n = 1
    for w in str:gmatch("([^" .. sep .. "]*)") do
        ret[n] = ret[n] or w:gsub("^%s*(.-)%s*$", "%1") -- strip whitespace
        if w ~= "" then
            ret[n] = w
            n = n + 1
        end
    end
    return ret
end

function JWTAuthHandler:access(conf)
    -- get the JWT from the shared context
    local token = kong.ctx.shared.authenticated_jwt_token
    if not token then
        kong.log.err("The JWT token cannot be found, make sure that a JWT plugin is enabled")
        return kong.response.exit(403, { message = "You cannot consume this service" })
    end

    -- decode token to get roles claim
    local jwt, err = jwt_decoder:new(token)
    if err then
        return kong.response.exit(401, { message = "Bad token; " .. tostring(err) })
    end

    local msg_error_all = conf.msg_error_all

    local msg_error_any = conf.msg_error_any
    local msg_error_not_roles_claimed = conf.msg_error_not_roles_claimed
    local roles_cfg = conf.roles
    local claims = jwt.claims
    local roles = claims[conf.roles_claim_name]
    local roles_table = {}
    
    -- check if no roles claimed..
    if not roles then
        return kong.response.exit(403, { message = msg_error_not_roles_claimed })
    end
    -- if the claim is a string (single role), make it a table
    if type(roles) == "string" then
        if string.find(roles, ",") then
            roles_table = split(roles, ",")
        else
            table.insert(roles_table, roles)
        end
        roles = roles_table
    end
        if type(conf.roles) == "table" then
        -- in declarative db-less setup the roles can be separated by a space
        if string.find(conf.roles[1], " ") then
            conf_roles_table = split(conf.roles[1], " ")
        end
        if string.find(conf.roles[1], ",") then
            conf_roles_table = split(conf.roles[1], ",")
        end
        conf.roles = conf_roles_table
    end

    local err_detail_fmt = "The permitted role for this invocation is [%s] and yours role are [%s]"
    if conf.policy == policy_ANY and not role_in_roles_claim(roles_cfg, roles) then
        return kong.response.exit(403, {
            detail = string.format(err_detail_fmt, table.concat(roles_cfg, ", "), table.concat(roles, ", ")),
            message = msg_error_any
        })
    end

    if conf.policy == policy_ALL and not all_roles_in_roles_claim(roles_cfg, roles) then
        return kong.response.exit(403, {
            detail = "The permitted role for this invocation is [" .. table.concat(roles_cfg, ", ") .. "] and yours role are [" .. table.concat(roles, ", ") .. "]",
            message = msg_error_all
        })
    end

end

return JWTAuthHandler
