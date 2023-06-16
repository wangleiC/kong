--Copyright 2021 The casbin Authors. All Rights Reserved.
--
--Licensed under the Apache License, Version 2.0 (the "License");
--you may not use this file except in compliance with the License.
--You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
--Unless required by applicable law or agreed to in writing, software
--distributed under the License is distributed on an "AS IS" BASIS,
--WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--See the License for the specific language governing permissions and
--limitations under the License.
-- judge str not empty: not nil && ~= ''

local method_type = {"GET", "POST"}
local authority_mode_type = {"RBAC", "ABAC", "ACL"}

local function isNotEmptyStr(str)
    return str and (string.len(tostring(str)) > 0)
end

-- judge if an array contains an element
local function contains(ele, arr)
    for _, value in pairs(arr) do
        if ele == value then
          return true
        end
    end
    return false
end

return {
    name = "kong-interface-check",
    fields = {
        {config = {
            type = "record",
            fields = {
                {param_method = {required = true, type = "string"}},
                {param_url = {required = true, type = "string"}},
                {authority_mode = {required = true, type = "string"}},
                {timeout = {required = true, type = "string"}},
            },
            --对配置进行额外的验证  -- todo 正则表达验证某些字段
            custom_validator = function (config)
                if isNotEmptyStr(config.param_method )  and isNotEmptyStr(config.param_url ) 
                and isNotEmptyStr(config.authority_mode )  and isNotEmptyStr(config.timeout )  
                --下边限制枚举
                and  contains(config.param_method, method_type)
                and  contains(config.authority_mode, authority_mode_type) then
                    return true
                end
                return false
          end
        }}
    }
}