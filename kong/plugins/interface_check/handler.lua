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

local http = require("socket.http")
local ltn12 = require("ltn12")
local get_headers = ngx.req.get_headers
--下面的参数时在插件新增时预先弄好的 可能在conf中
local kong_response = kong.response
local param_method = "GET"
local param_url = "https://127.0.0.1"
--默认casbin的RBAC模式
local authority_mode = "RBAC"
local timeout = 5

local plugin = {
    PRIORITY = 1000,
    VERSION = "0.1",
}

--校验是否符合白羊写的认证方式的权限
local checkAuthority = function (get_headers)
  local response_body = {}
  local request_body = ""
  local request_options = {
    url = param_url,
    method = param_method,
    headers = get_headers,
    source = ltn12.source.string(request_body),
    sink = ltn12.sink.table(response_body),
    timeout = timeout
  }

  local result, status_code, response_headers, status_line = http.request(request_options) {
    --ltn12.sink.table(response_body) 是一个 ltn12 提供的过滤器，用于将接收到的数据写入 Lua 表中。
    sink = ltn12.sink.table(response_body)
  }
  print(table.concat(response_body))
  
  if result and status_code == 200 then
    if response_body == 200 then
      print(table.concat(response_body))

    else
      print("Request failed: " .. status_line)
      return kong_response.exit(403, "Access denied")
    end
  
  else
    print("Access failed")
    return kong_response.exit(403, "Access denied")
  end
end

--conf 我怀疑是插件添加时增加的初始化参数信息
function plugin:access(conf)
    local path = ngx.var.request_uri
    local method = ngx.var.request_method
    local username = get_headers()[conf.username]
    --casbin的不同模式
    if authority_mode == "RBAC" then
      if path and method and username then
        return checkAuthority(get_headers)
      end
    else
        return kong_response.exit(403, "No authority mode match")
    end
end
    

return plugin