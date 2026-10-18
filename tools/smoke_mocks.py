"""Protocol mock prelude, part 2, for the NSE smoke-test harness.

GraphQL HTTP dispatch plus DNS mocks. Concatenated after MOCK_PRELUDE
and before the part-3 prelude at runtime; see smoke_nse.py.
"""

MOCK_PRELUDE_EXTRA = r"""
local function gql_mock_response(scenario, path, options, data, method)
  local secure = scenario == "graphql-secure"
  local header = {}
  local rawheader = {}
  local function add(name, value)
    header[real_string.lower(name)] = value
    rawheader[#rawheader + 1] = name .. ": " .. value
  end

  local raw_path = tostring(path or "/")
  local qstring = raw_path:match("%?[^#]*$") or ""
  local clean_path = raw_path:match("^[^?]*") or raw_path
  local headers = {}
  if options and options.header then
    for k, v in pairs(options.header) do headers[real_string.lower(k)] = tostring(v) end
  end
  if options and options.headers then
    for k, v in pairs(options.headers) do headers[real_string.lower(k)] = tostring(v) end
  end
  local ct = headers["content-type"] or ""
  local accept = headers["accept"] or ""
  local req_method = method or "GET"

  if GQL_IDE_PATHS[clean_path] then
    if secure then
      add("Content-Type", "application/json")
      return { status = 404, ["status-line"] = "HTTP/1.1 404 Not Found\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Not found"}]}' }
    end
    if GQL_IDE_PATHS[clean_path] == "graphiql" then
      add("Content-Type", "text/html; charset=utf-8")
      return { status = 200, ["status-line"] = "HTTP/1.1 200 OK\r\n", header = header, rawheader = rawheader, body = gql_graphiql_html() }
    end
    add("Content-Type", "text/html; charset=utf-8")
    return { status = 200, ["status-line"] = "HTTP/1.1 200 OK\r\n", header = header, rawheader = rawheader, body = gql_play_html() }
  end

  if not GQL_ENDPOINTS[clean_path] then
    add("Content-Type", "application/json")
    return { status = 404, ["status-line"] = "HTTP/1.1 404 Not Found\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Not found"}]}' }
  end

  if real_string.lower(accept):find("text/event%-stream") then
    if secure then
      add("Content-Type", "application/json")
      return { status = 406, ["status-line"] = "HTTP/1.1 406 Not Acceptable\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Server-Sent Events subscriptions are disabled"}]}' }
    end
    local sse = ":ok\n\nid: 1\nevent: next\ndata: {\"type\":\"subscription_data\",\"id\":\"1\",\"payload\":{\"orderStatus\":{\"orderId\":\"o_501\",\"status\":\"PAID\"}}}\n\n"
    add("Content-Type", "text/event-stream")
    add("Cache-Control", "no-cache")
    return { status = 200, ["status-line"] = "HTTP/1.1 200 OK\r\n", header = header, rawheader = rawheader, body = sse }
  end

  local query = nil
  local has_variables = false
  if req_method == "GET" then
    local qs = gql_urldecode(qstring)
    local q = qs:match("query=([^&]+)")
    if q then query = gql_unescape_query(q) end
    if qs:find("variables=", 1, true) then has_variables = true end
  else
    local body = tostring(data or "")
    local trimmed = body:match("^%s*(.-)%s*$")
    if secure and #ct > 0 and not real_string.lower(ct):find("application/json") and not real_string.lower(ct):find("application/x%-www%-form%-urlencoded") then
      add("Content-Type", "application/json")
      return { status = 415, ["status-line"] = "HTTP/1.1 415 Unsupported Media Type\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Content-Type must be application/json or application/x-www-form-urlencoded","extensions":{"code":"UNSUPPORTED_CONTENT_TYPE"}}]}' }
    end
    if trimmed:sub(1, 1) == "[" then
      if secure then
        add("Content-Type", "application/json")
        return { status = 400, ["status-line"] = "HTTP/1.1 400 Bad Request\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Batched queries are disabled on this server","extensions":{"code":"BATCH_DISABLED"}}]}' }
      end
      local elements = gql_split_top_level_array(trimmed)
      local results = {}
      for idx, elem in ipairs(elements) do
        local q = gql_extract_json_string(elem, 'query')
        if q then
          local has_v = elem:find('"variables"') ~= nil
          local st, res = gql_execute_single(secure, gql_unescape_query(q), has_v, "POST")
          results[idx] = gql_response_body(st, res)
        else
          results[idx] = '{"errors":[{"message":"Missing query"}]}'
        end
      end
      add("Content-Type", "application/json")
      return { status = 200, ["status-line"] = "HTTP/1.1 200 OK\r\n", header = header, rawheader = rawheader, body = "[" .. table.concat(results, ",") .. "]" }
    end
    if real_string.lower(ct):find("application/x%-www%-form%-urlencoded") then
      local q = body:match("query=([^\r\n&]*)")
      if q then query = gql_unescape_query(gql_urldecode(q)) end
      if body:find("variables=", 1, true) then has_variables = true end
    else
      local q = gql_extract_json_string(body, 'query')
      if q then query = q end
      if body:find('"variables"') then has_variables = true end
      if body:find('"persistedQuery"') and not query then
        if secure then
          add("Content-Type", "application/json")
          return { status = 400, ["status-line"] = "HTTP/1.1 400 Bad Request\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"PersistedQueryNotSupported","extensions":{"code":"PERSISTED_QUERY_NOT_SUPPORTED"}}]}' }
        end
        add("Content-Type", "application/json")
        return { status = 400, ["status-line"] = "HTTP/1.1 400 Bad Request\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"PersistedQueryNotFound","extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}' }
      end
    end
  end

  if not query then
    if req_method == "GET" and real_string.lower(accept):find("text/html") and not secure then
      add("Content-Type", "text/html; charset=utf-8")
      return { status = 200, ["status-line"] = "HTTP/1.1 200 OK\r\n", header = header, rawheader = rawheader, body = gql_graphiql_html() }
    end
    add("Content-Type", "application/json")
    if req_method == "GET" then
      return { status = 400, ["status-line"] = "HTTP/1.1 400 Bad Request\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Must provide query string."}]}' }
    end
    return { status = 400, ["status-line"] = "HTTP/1.1 400 Bad Request\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Must provide a query string."}]}' }
  end

  local open_count = 0
  local close_count = 0
  for ch in query:gmatch(".") do
    if ch == "{" then open_count = open_count + 1
    elseif ch == "}" then close_count = close_count + 1 end
  end
  if open_count ~= close_count then
    add("Content-Type", "application/json")
    if not secure then
      add("X-GraphQL-Trace", "trc_8f2a91c4d7e0")
      add("X-Debug", "enabled")
    end
    if not secure then
      add("X-Powered-By", "Strawberry GraphQL 0.215.0")
    else
      add("X-Powered-By", "Apollo Server 4.9.3")
      add("X-Content-Type-Options", "nosniff")
    end
    return { status = 400, ["status-line"] = "HTTP/1.1 400 Bad Request\r\n", header = header, rawheader = rawheader, body = '{"errors":[{"message":"Syntax Error: Expected Name, found <EOF>.","locations":[{"line":1,"column":28}],"debug":' .. (secure and "null" or ('"' .. GQL_DEBUG_TRACES.generic:gsub('"', '\\"'):gsub("\n", "\\n") .. '"')) .. '}]}' }
  end

  local status, result = gql_execute_single(secure, query, has_variables, req_method)
  local body
  if type(result) == "table" and result.raw then
    body = result.raw
  else
    if not secure and status >= 400 and type(result) == "table" and result.errors then
      local kind = "generic"
      local msg = tostring(result.errors[1] and result.errors[1].message or "")
      if msg:find("Cannot query field") or msg:find("must have a selection") then
        kind = "field"
      elseif msg:find("Argument") or msg:find("Variable") or msg:find("Expected value") or msg:find("Unknown directive") then
        kind = "validation"
      end
      result = { data = nil, errors = result.errors }
      result.errors[1].debug = GQL_DEBUG_TRACES[kind]
    end
    body = gql_encode(result)
  end
  add("Content-Type", "application/json")
  if not secure and status >= 400 then
    add("X-GraphQL-Trace", "trc_8f2a91c4d7e0")
    add("X-Debug", "enabled")
  end
  if not secure then
    add("X-Powered-By", "Strawberry GraphQL 0.215.0")
  else
    add("X-Powered-By", "Apollo Server 4.9.3")
    add("X-Content-Type-Options", "nosniff")
  end
  local reason = " OK"
  if status == 400 then reason = " Bad Request"
  elseif status == 404 then reason = " Not Found"
  elseif status == 405 then reason = " Method Not Allowed"
  elseif status == 415 then reason = " Unsupported Media Type"
  elseif status == 406 then reason = " Not Acceptable" end
  return {
    status = status,
    ["status-line"] = "HTTP/1.1 " .. status .. reason .. "\r\n",
    header = header,
    rawheader = rawheader,
    body = body,
  }
end

local function byte_xor(a, b)
  local r = 0
  for i = 0, 7 do
    local ca = math.floor(a / 2 ^ i) % 2
    local cb = math.floor(b / 2 ^ i) % 2
    if ca + cb == 1 then
      r = r + 2 ^ i
    end
  end
  return r
end

local function gql_ws_unmask(sent)
  if type(sent) ~= "string" or #sent < 6 then
    return sent
  end
  local second = sent:byte(2)
  if second < 128 then
    return sent
  end
  local len = second % 128
  local off = 2
  if len == 126 then
    if #sent < 8 then return sent end
    len = sent:byte(3) * 256 + sent:byte(4)
    off = 4
  elseif len == 127 then
    if #sent < 14 then return sent end
    len = 0
    for i = 3, 10 do
      len = len * 256 + sent:byte(i)
    end
    off = 10
  end
  local payload_off = off + 5
  if #sent < payload_off + len - 1 then
    return sent
  end
  local mask = sent:sub(off + 1, off + 4)
  local payload = sent:sub(payload_off, payload_off + len - 1)
  local out = {}
  for i = 1, len do
    out[i] = real_string.char(byte_xor(payload:byte(i), mask:byte(((i - 1) % 4) + 1)))
  end
  return real_table.concat(out, "")
end

local function gql_ws_reply(scenario, sent, sock)
  sent = gql_ws_unmask(sent)
  local lower = real_string.lower(sent)
  if real_string.find(lower, "upgrade: websocket") then
    sock.wsstate = 1
    local key = real_string.match(sent, "Sec%-WebSocket%-Key:%s*([%w%+/=]+)")
    local accept = "bW9jaw=="
    if key then
      accept = mock_sha1_b64(key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
    end
    if scenario == "graphql" then
      return "HTTP/1.1 101 Switching Protocols\r\n"
        .. "Upgrade: websocket\r\n"
        .. "Connection: Upgrade\r\n"
        .. "Sec-WebSocket-Accept: " .. accept .. "\r\n"
        .. "Sec-WebSocket-Protocol: graphql-transport-ws\r\n"
        .. "X-Powered-By: Strawberry GraphQL 0.215.0\r\n\r\n"
    end
    return "HTTP/1.1 426 Upgrade Required\r\n"
      .. "Connection: Upgrade\r\n"
      .. "Content-Type: application/json\r\n\r\n"
      .. '{"errors":[{"message":"WebSocket subscriptions are disabled","extensions":{"code":"WS_DISABLED"}}]}'
  end
  if sock.wsstate ~= nil then
    if real_string.find(lower, "connection_init") then
      if scenario == "graphql" then
        return '{"type":"connection_ack"}\r\n'
      end
      return '{"type":"connection_error","payload":"Unauthorized"}\r\n'
    end
    if real_string.find(lower, "keep_alive") or real_string.find(lower, "keepalive") then
      if scenario == "graphql" then
        return '{"type":"connection_keep_alive"}\r\n'
      end
      return '{"type":"connection_error","payload":"Unauthorized"}\r\n'
    end
    if real_string.find(lower, "\"subscribe\"") then
      if scenario == "graphql" then
        return '{"type":"next","id":"s_1","payload":{"notification":{"id":"n_1","message":"Welcome aboard"}}}\r\n'
      end
      return '{"type":"connection_error","payload":"Unauthorized"}\r\n'
    end
  end
  return nil
end


function mock_http_response(scenario, path, options, data, method)
  if scenario == "graphql" or scenario == "graphql-secure" then
    return gql_mock_response(scenario, path, options, data, method)
  end

  local header = {}
  local rawheader = {}
  local body = ""
  local status = 200

  local function add(name, value)
    header[real_string.lower(name)] = value
    rawheader[#rawheader + 1] = name .. ": " .. value
  end

  local raw_doh_path = tostring(path or "")
  local doh_path = real_string.lower(raw_doh_path)
  if doh_path == "/dns-query" or real_string.find(doh_path, "^/dns%-query[?&]") then
    local accept = ""
    if options and type(options.headers) == "table" then
      for k, v in pairs(options.headers) do
        if real_string.lower(tostring(k)) == "accept" then
          accept = real_string.lower(tostring(v))
        end
      end
    end
    if real_string.find(accept, "application/dns%-message") then
      local dns_param = real_string.match(raw_doh_path, "dns=([^&]+)")
      local name_param = real_string.match(raw_doh_path, "name=([^&]+)")
      if name_param then
        name_param = real_string.gsub(name_param, "%-%%(%x%x)", function(h)
          return real_string.char(tonumber(h, 16))
        end)
      end
      body = doh_dns_answer(dns_param or name_param)
      add("Content-Type", "application/dns-message")
      add("Access-Control-Allow-Origin", "*")
    else
      status = 406
      body = "<html><body>406 Not Acceptable</body></html>"
      add("Content-Type", "text/html")
    end
    return {
      status = status,
      ["status-line"] = "HTTP/1.1 " .. status .. (status == 200 and " OK" or " Not Acceptable") .. "\r\n",
      header = header,
      rawheader = rawheader,
      body = body,
      location = header["location"],
    }
  end

  if scenario == "plain" then
    body = "<html><body><h1>It works</h1>"
      .. "<form action='http://insecure.local/login'><input></form>"
      .. "<script src='http://cdn.example.com/a.js'></script></body></html>"
    add("Server", "Apache/2.4.49 (Ubuntu)")
    add("X-Powered-By", "PHP/7.4.3")
    add("X-AspNet-Version", "4.0.30319")
    add("X-Generator", "WordPress 5.9")
    add("Cache-Control", "public, max-age=3600")
    add("Vary", "Accept-Encoding")
    add("Set-Cookie", "PHPSESSID=abc123; path=/")
    add("Set-Cookie", "remember_me=1; Domain=example.com; Max-Age=31536000")
    add("Access-Control-Allow-Origin", "*")
    add("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data:; object-src *")
    add("Strict-Transport-Security", "max-age=300")
    add("X-XSS-Protection", "1; mode=block")
    add("NEL", "[{\"report_to\":\"default\",\"max_age\":999999999,\"success_fraction\":1.0}]")
    add("Permissions-Policy", "camera=*, microphone=(self https://ok.example), bogus=()")
    add("Referrer-Policy", "unsafe-url")
    add("X-Frame-Options", "ALLOW-FROM http://evil.example")
    add("Feature-Policy", "geolocation *")
  elseif scenario == "hardened" then
    body = "<html><body>ok</body></html>"
    add("Content-Security-Policy",
      "default-src 'self'; script-src 'nonce-abc123XYZ' 'strict-dynamic'; object-src 'none'; "
      .. "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; report-uri https://r.example/csp")
    add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    add("X-Content-Type-Options", "nosniff")
    add("Referrer-Policy", "no-referrer")
    add("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    add("Cross-Origin-Opener-Policy", "same-origin")
    add("Cross-Origin-Embedder-Policy", "require-corp")
    add("Cross-Origin-Resource-Policy", "same-origin")
    add("Cache-Control", "no-store, private")
    add("Set-Cookie", "sid=xyz; Secure; HttpOnly; SameSite=Strict; Path=/")
    add("X-XSS-Protection", "0")
    add("NEL", "[{\"report_to\":\"default\",\"max_age\":604800}]")
  elseif scenario == "waf" then
    status = 403
    body = "<html><head><title>Attention Required! | Cloudflare</title></head><body>blocked</body></html>"
    add("Server", "cloudflare")
    add("CF-RAY", "1234-FRA")
  elseif scenario == "empty" then
    status = 204
    body = ""
  elseif scenario == "error" then
    status = 500
    body = "<pre>Traceback: debug stack trace at /var/www/app.py line 12</pre>"
    add("Server", "gunicorn")
  elseif scenario == "redirect" then
    status = 302
    body = ""
    add("Location", "http://target.example.com/login")
  elseif scenario == "git" then
    local lowered = real_string.lower(path or "")
    if real_string.find(lowered, ".git/config", 1, true) or real_string.find(lowered, ".gitmodules", 1, true) then
      body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
        .. "[remote \"origin\"]\n\turl = https://deploy:s3cr3tToken123@git.example.com/internal/app.git\n"
        .. "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\n\tremote = origin\n"
        .. "\tmerge = refs/heads/master\n[user]\n\temail = dev@example.com\n"
      add("Content-Type", "text/plain")
      status = 200
      return { status = status, ["status-line"] = "HTTP/1.1 200 OK\r\n", header = header,
        rawheader = rawheader, body = body, location = nil }
    elseif real_string.find(lowered, ".git/head", 1, true) then
      body = "ref: refs/heads/master\n"
    elseif real_string.find(lowered, "info/refs", 1, true) and real_string.find(lowered, "service=", 1, true) then
      body = "001e# service=git-upload-pack\n0000"
    elseif real_string.find(lowered, ".git/packed-refs", 1, true) then
      body = "# pack-refs with: peeled fully-peeled sorted \n"
        .. "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432 refs/heads/master\n"
        .. "1234567890abcdef1234567890abcdef12345678 refs/tags/v1.0\n"
    elseif real_string.find(lowered, ".git/logs/head", 1, true) then
      body = "0000000000000000000000000000000000000000 9f8e7d6c5b4a39281706f5e4d3c2b1a098765432 "
        .. "Jane Developer <jane@example.com> 1700000000 +0000\tcommit (initial): first commit\n"
    elseif real_string.find(lowered, "objects/info/packs", 1, true) then
      body = "P pack-9f8e7d6c5b4a39281706f5e4d3c2b1a098765432.pack\n\n"
    elseif real_string.find(lowered, ".pack", 1, true) then
      body = "PACK" .. string.char(0, 0, 0, 2) .. string.char(0, 0, 0, 42) .. real_string.rep("z", 200)
    elseif real_string.find(lowered, ".git/index", 1, true) then
      body = "DIRC" .. string.char(0, 0, 0, 2) .. string.char(0, 0, 0, 120) .. real_string.rep("\0", 120 * 62)
    elseif real_string.find(lowered, ".git/shallow", 1, true) then
      body = "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432\n"
    elseif real_string.find(lowered, ".git/commit_editmsg", 1, true) then
      body = "fix: rotate DB password\nAWS_SECRET_ACCESS_KEY=AKIAABCDEFGHijKLMNOP\n"
    elseif real_string.find(lowered, ".git", 1, true) then
      body = "<html><head><title>Index of /.git</title></head><body><h1>Index of /.git</h1><pre>"
        .. "<a href=\"config\">config</a>\n<a href=\"HEAD\">HEAD</a>\n</pre></body></html>"
    else
      status = 404
      body = "<html><body>Not Found</body></html>"
    end
    return { status = status, ["status-line"] = "HTTP/1.1 " .. status .. " OK\r\n", header = header,
      rawheader = rawheader, body = body, location = nil }
  elseif scenario == "env" then
    local lowered = real_string.lower(path or "")
    if real_string.find(lowered, ".env", 1, true) or real_string.find(lowered, "wp-config", 1, true)
      or real_string.find(lowered, "docker-compose", 1, true) or real_string.find(lowered, "config.json", 1, true) then
      body = "# Laravel production environment\nAPP_NAME=Acme\nAPP_ENV=production\nAPP_KEY=base64:9xK2mP0qR7sT4uV1wX8yZ5aB2cD3eF6gH7iJ0kL1mN4=\n"
        .. "APP_DEBUG=true\nAPP_URL=https://acme.example.com\n\nLOG_CHANNEL=stack\n\n"
        .. "DB_CONNECTION=mysql\nDB_HOST=10.12.4.31\nDB_PORT=3306\nDB_DATABASE=acme_prod\nDB_USERNAME=acme_app\n"
        .. "DB_PASSWORD=Sup3rS3cretProdPass!\nDATABASE_URL=mysql://acme_app:Sup3rS3cretProdPass!@10.12.4.31:3306/acme_prod\n\n"
        .. "export REDIS_HOST=cache.internal.acme\nexport REDIS_PASSWORD=redisPass123\n\n"
        .. "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7example\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        .. "AWS_DEFAULT_REGION=eu-west-1\nAWS_BUCKET=acme-prod-assets\n\n"
        .. "MAIL_HOST=smtp.mailgun.org\nMAIL_PORT=587\nMAIL_USERNAME=postmaster@acme.example.com\nMAIL_PASSWORD=mailgunPass456\n\n"
        .. "STRIPE_SECRET_KEY=sk_live_51H8xYzKabcd12\nJWT_SECRET=changeme\nAPI_KEY=your_key_here\n"
        .. "SENTRY_DSN=https://abc123@o1234.ingest.sentry.io/5678\nMONGO_URI=mongodb://root:toor@10.12.4.40:27017/admin\n"
      add("Content-Type", "text/plain")
      add("Last-Modified", "Mon, 02 Jan 2023 10:00:00 GMT")
      return { status = 200, ["status-line"] = "HTTP/1.1 200 OK\r\n", header = header,
        rawheader = rawheader, body = body, location = nil }
    else
      return { status = 404, ["status-line"] = "HTTP/1.1 404 Not Found\r\n", header = header,
        rawheader = rawheader, body = "<html><body>404</body></html>", location = nil }
    end
  elseif scenario == "json" then
    body = '{"status":"ok","version":"1.2.3","data":{"id":1}}'
    add("Content-Type", "application/json")
    add("X-Request-Id", "9f8e7d6c")
  elseif scenario == "crawler" then
    if lpath_target(path) == "/robots.txt" or lpath_target(path) == "/robots.txt/" then
      body = "# generated by cms\n"
        .. "User-agent: *\n"
        .. "Disallow: /admin/\n"
        .. "Disallow: /backup/db_dump.sql\n"
        .. "Disallow: /phpmyadmin/\n"
        .. "Disallow: /internal/config.php\n"
        .. "Disallow: /logs/\n"
        .. "Disallow: /wp-admin/\n"
        .. "Allow: /wp-admin/admin-ajax.php\n"
        .. "Disallow: /private/*/export$\n"
        .. "Disallow:\n"
        .. "Crawl-delay: 10\n"
        .. "Noindex: /temp/\n"
        .. "bogus-field: value\n"
        .. "User-agent: Googlebot\n"
        .. "Disallow: /staging/\n"
        .. "Sitemap: https://target.example.com/sitemap.xml\n"
        .. "Sitemap: /news-sitemap.xml\n"
      add("Content-Type", "text/plain")
    elseif lpath_target(path) == "/sitemap.xml" then
      body = '<?xml version="1.0" encoding="UTF-8"?>\n'
        .. '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n'
        .. '        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">\n'
        .. '  <url><loc>https://target.example.com/</loc><lastmod>2026-01-04</lastmod>'
        .. '<changefreq>daily</changefreq><priority>1.0</priority></url>\n'
        .. '  <url><loc>https://target.example.com/products/widget</loc>'
        .. '<lastmod>1994-01-01</lastmod></url>\n'
        .. '  <url><loc>http://target.example.com/legacy/page</loc><lastmod>2031-13-45</lastmod>'
        .. '<image:image><image:loc>https://target.example.com/img/a.jpg</image:loc></image:image></url>\n'
        .. '  <url><loc>https://partner.example.org/deal</loc></url>\n'
        .. '  <url><loc>https://target.example.com/account?sessionid=abc123</loc></url>\n'
        .. '  <url><loc>https://target.example.com/admin/config.php.bak</loc></url>\n'
        .. '</urlset>\n'
      add("Content-Type", "application/xml")
    elseif lpath_target(path) == "/news-sitemap.xml" then
      body = '<?xml version="1.0" encoding="UTF-8"?>\n'
        .. '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        .. '  <sitemap><loc>https://target.example.com/news-2026.xml</loc>'
        .. '<lastmod>2026-08-30</lastmod></sitemap>\n'
        .. '  <sitemap><loc>https://target.example.com/news-2025.xml</loc></sitemap>\n'
        .. '</sitemapindex>\n'
      add("Content-Type", "application/xml")
    elseif real_string.find(path, "^/nse%-robots%-") then
      status = 404
      body = "<html><body>404</body></html>"
    else
      body = "<html><head><meta name=\"robots\" content=\"noindex, nofollow\">"
        .. "<title>page</title></head><body><h1>It works</h1></body></html>"
      add("X-Robots-Tag", "noindex, noarchive, max-snippet:20")
      add("Content-Type", "text/html")
    end
  elseif scenario == "policy" then
    if real_string.find(path, "^https?://") then
      body = '<?xml version="1.0"?>\n'
        .. '<cross-domain-policy>\n'
        .. '  <site-control permitted-cross-domain-policies="all"/>\n'
        .. '  <allow-access-from domain="*" secure="false"/>\n'
        .. '  <allow-access-from domain="*.example.com"/>\n'
        .. '  <allow-access-from domain="198.51.100.23"/>\n'
        .. '  <allow-access-from domain="partner.github.io"/>\n'
        .. '  <allow-access-from domain="cdn.ngrok.io"/>\n'
        .. '  <allow-http-request-headers-from domain="*" headers="*" secure="false"/>\n'
        .. '  <allow-http-request-headers-from domain="api.partner.net" headers="Authorization,X-CSRF-Token"/>\n'
        .. '</cross-domain-policy>\n'
      add("Content-Type", "text/x-cross-domain-policy")
    elseif lpath_target(path) == "/crossdomain.xml" then
      body = '<?xml version="1.0"?>\n'
        .. '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n'
        .. '<cross-domain-policy>\n'
        .. '  <!-- added for the partner widget -->\n'
        .. '  <site-control permitted-cross-domain-policies="all"/>\n'
        .. '  <allow-access-from domain="*" secure="false"/>\n'
        .. '  <allow-access-from domain="*.example.com"/>\n'
        .. '  <allow-access-from domain="198.51.100.23"/>\n'
        .. '  <allow-access-from domain="partner.github.io"/>\n'
        .. '  <allow-http-request-headers-from domain="*" headers="*" secure="false"/>\n'
        .. '  <allow-http-request-headers-from domain="api.partner.net" headers="Authorization,X-CSRF-Token"/>\n'
        .. '</cross-domain-policy>\n'
      add("Content-Type", "text/x-cross-domain-policy")
    elseif lpath_target(path) == "/clientaccesspolicy.xml" then
      body = '<?xml version="1.0"?>\n'
        .. '<access-policy>\n'
        .. '  <cross-domain-access>\n'
        .. '    <policy>\n'
        .. '      <allow-from http-request-headers="true">\n'
        .. '        <domain uri="*"/>\n'
        .. '      </allow-from>\n'
        .. '      <grant-to>\n'
        .. '        <resource path="/" include-subpaths="true"/>\n'
        .. '      </grant-to>\n'
        .. '    </policy>\n'
        .. '  </cross-domain-access>\n'
        .. '</access-policy>\n'
      add("Content-Type", "text/xml")
    elseif lpath_target(path) == "/uploads/crossdomain.xml" then
      body = '<?xml version="1.0"?>\n'
        .. '<cross-domain-policy>\n'
        .. '  <site-control permitted-cross-domain-policies="none"/>\n'
        .. '</cross-domain-policy>\n'
      add("Content-Type", "text/xml")
    elseif lpath_target(path) == "/crossdomain.txt" then
      body = '<?xml version="1.0"?>\n'
        .. '<cross-domain-policy>\n'
        .. '  <allow-access-from domain="legacy.s3.amazonaws.com"/>\n'
        .. '  <allow-access-from domain=".example.com"/>\n'
        .. '  <allow-access-from/>\n'
        .. '</cross-domain-policy>\n'
      add("Content-Type", "text/plain")
    else
      body = "<html><head><title>It works</title></head><body><h1>It works</h1></body></html>"
      add("Cross-Domain-Policy", "/assets/crossdomain.xml")
      add("Content-Type", "text/html")
    end
  elseif scenario == "phpinfo" then
    if lpath_target(path) == "/phpinfo.php" or lpath_target(path) == "/admin/info.php" then
      body = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" "
        .. "\"DTD/xhtml1-transitional.dtd\">\n"
        .. "<html><head><style type=\"text/css\">body {background-color: #ffffff; color: #000000;}"
        .. "body, td, th, h1, h2 {font-family: sans-serif;}h1 {font-size: 150%;}h2 {font-size: 125%;}"
        .. ".center {text-align: center;}.center table {margin: 0 auto; text-align: left;}"
        .. ".center th {text-align: center !important;}td, th {border: 1px solid #666666;}"
        .. "th {background: #9999cc; color: #000000;}h1 {background: #666699; color: #ffffff;}"
        .. ".e {background-color: #ccccff;}.v {background-color: #dddddd;}.h {background-color: #9999cc;}"
        .. "</style><title>phpinfo()</title></head><body><div class=\"center\">\n"
        .. "<h1 class=\"p\">PHP Version 5.6.40</h1>\n"
        .. "<table><tr><td class=\"e\">System </td><td class=\"v\">Linux web-01 4.19.0 #1 SMP x86_64 </td></tr>\n"
        .. "<tr><td class=\"e\">Build Date </td><td class=\"v\">Jan 10 2019 13:20:11 </td></tr>\n"
        .. "<tr><td class=\"e\">Server API </td><td class=\"v\">CGI/FastCGI </td></tr>\n"
        .. "<tr><td class=\"e\">Configuration File (php.ini) Path </td>"
        .. "<td class=\"v\">/etc/php5/cgi </td></tr>\n"
        .. "<tr><td class=\"e\">Loaded Configuration File </td>"
        .. "<td class=\"v\">/etc/php5/cgi/php.ini </td></tr>\n"
        .. "<tr><td class=\"e\">Scan for additional .ini files in </td>"
        .. "<td class=\"v\">/etc/php5/cgi/conf.d </td></tr>\n"
        .. "<tr><td class=\"e\">DOCUMENT_ROOT </td><td class=\"v\">/var/www/html </td></tr>\n"
        .. "<tr><td class=\"e\">Registered PHP Streams</td>"
        .. "<td class=\"v\">https, http, ftp, ftps, compress.zlib, php, file, glob, data, phar</td></tr>\n"
        .. "<tr><td class=\"e\">Registered Stream Socket Transports</td>"
        .. "<td class=\"v\">tcp, udp, unix, udg, ssl, sslv3, tls</td></tr>\n"
        .. "<tr><td class=\"e\">Zend Extension Build </td><td class=\"v\">API220131226,NTS </td></tr>\n"
        .. "<tr><td class=\"e\">PHP Extension Build </td><td class=\"v\">API20131226,NTS </td></tr>\n"
        .. "</table>\n"
        .. "<h2>Configuration</h2>\n"
        .. "<h2>Core</h2>\n"
        .. "<table><tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n"
        .. "<tr><td class=\"e\">allow_url_fopen</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">allow_url_include</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">Off</td></tr>\n"
        .. "<tr><td class=\"e\">display_errors</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">display_startup_errors</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">Off</td></tr>\n"
        .. "<tr><td class=\"e\">log_errors</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n"
        .. "<tr><td class=\"e\">expose_php</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">open_basedir</td><td class=\"v\">no value</td>"
        .. "<td class=\"v\">no value</td></tr>\n"
        .. "<tr><td class=\"e\">disable_functions</td><td class=\"v\">no value</td>"
        .. "<td class=\"v\">no value</td></tr>\n"
        .. "<tr><td class=\"e\">enable_dl</td><td class=\"v\">On</td><td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">register_globals</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">safe_mode</td><td class=\"v\">Off</td><td class=\"v\">Off</td></tr>\n"
        .. "<tr><td class=\"e\">magic_quotes_gpc</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">include_path</td><td class=\"v\">.:/usr/share/php:/var/www/lib</td>"
        .. "<td class=\"v\">.:/usr/share/php</td></tr>\n"
        .. "<tr><td class=\"e\">error_reporting</td><td class=\"v\">32767</td>"
        .. "<td class=\"v\">32767</td></tr>\n"
        .. "<tr><td class=\"e\">memory_limit</td><td class=\"v\">256M</td>"
        .. "<td class=\"v\">128M</td></tr>\n"
        .. "<tr><td class=\"e\">max_execution_time</td><td class=\"v\">300</td>"
        .. "<td class=\"v\">30</td></tr>\n"
        .. "</table>\n"
        .. "<h2>cgi-fcgi</h2>\n"
        .. "<table><tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n"
        .. "<tr><td class=\"e\">cgi.fix_pathinfo</td><td class=\"v\">1</td>"
        .. "<td class=\"v\">1</td></tr>\n"
        .. "<tr><td class=\"e\">cgi.force_redirect</td><td class=\"v\">0</td>"
        .. "<td class=\"v\">1</td></tr>\n"
        .. "<tr><td class=\"e\">cgi.discard_path</td><td class=\"v\">0</td>"
        .. "<td class=\"v\">0</td></tr>\n"
        .. "</table>\n"
        .. "<h2>session</h2>\n"
        .. "<table><tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n"
        .. "<tr><td class=\"e\">session.save_path</td><td class=\"v\">/var/lib/php5/sessions</td>"
        .. "<td class=\"v\">/var/lib/php5/sessions</td></tr>\n"
        .. "<tr><td class=\"e\">session.cookie_httponly</td><td class=\"v\">0</td>"
        .. "<td class=\"v\">0</td></tr>\n"
        .. "<tr><td class=\"e\">session.cookie_secure</td><td class=\"v\">0</td>"
        .. "<td class=\"v\">0</td></tr>\n"
        .. "<tr><td class=\"e\">session.use_strict_mode</td><td class=\"v\">0</td>"
        .. "<td class=\"v\">0</td></tr>\n"
        .. "<tr><td class=\"e\">session.use_only_cookies</td><td class=\"v\">0</td>"
        .. "<td class=\"v\">1</td></tr>\n"
        .. "<tr><td class=\"e\">session.use_trans_sid</td><td class=\"v\">1</td>"
        .. "<td class=\"v\">0</td></tr>\n"
        .. "</table>\n"
        .. "<h2>mysql</h2>\n"
        .. "<table><tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n"
        .. "<tr><td class=\"e\">mysql.default_host</td><td class=\"v\">db-01.internal</td>"
        .. "<td class=\"v\">db-01.internal</td></tr>\n"
        .. "<tr><td class=\"e\">mysql.default_user</td><td class=\"v\">app_rw</td>"
        .. "<td class=\"v\">app_rw</td></tr>\n"
        .. "<tr><td class=\"e\">mysql.default_password</td><td class=\"v\">Sup3rS3cret!</td>"
        .. "<td class=\"v\">Sup3rS3cret!</td></tr>\n"
        .. "<tr><td class=\"e\">mysqli.default_socket</td>"
        .. "<td class=\"v\">/var/run/mysqld/mysqld.sock</td>"
        .. "<td class=\"v\">/var/run/mysqld/mysqld.sock</td></tr>\n"
        .. "</table>\n"
        .. "<h2>xdebug</h2>\n"
        .. "<table><tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n"
        .. "<tr><td class=\"e\">xdebug.remote_enable</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">xdebug.remote_connect_back</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">On</td></tr>\n"
        .. "<tr><td class=\"e\">xdebug.remote_host</td><td class=\"v\">10.0.0.9</td>"
        .. "<td class=\"v\">localhost</td></tr>\n"
        .. "<tr><td class=\"e\">xdebug.profiler_enable</td><td class=\"v\">On</td>"
        .. "<td class=\"v\">Off</td></tr>\n"
        .. "</table>\n"
        .. "<h2>Environment</h2>\n"
        .. "<table><tr class=\"h\"><th>Variable</th><th>Value</th></tr>\n"
        .. "<tr><td class=\"e\">DATABASE_URL</td>"
        .. "<td class=\"v\">mysql://app_rw:Sup3rS3cret!@db-01.internal:3306/shop</td></tr>\n"
        .. "<tr><td class=\"e\">AWS_SECRET_ACCESS_KEY</td>"
        .. "<td class=\"v\">wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr>\n"
        .. "<tr><td class=\"e\">APP_KEY</td><td class=\"v\">base64:Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0</td></tr>\n"
        .. "<tr><td class=\"e\">STRIPE_API_TOKEN</td><td class=\"v\">sk_live_4eC39HqLyjWDar</td></tr>\n"
        .. "<tr><td class=\"e\">SMTP_PASSWORD</td><td class=\"v\">mailgun-p@ss</td></tr>\n"
        .. "<tr><td class=\"e\">REDIS_PASSWORD</td><td class=\"v\">no value</td></tr>\n"
        .. "<tr><td class=\"e\">KUBERNETES_SERVICE_HOST</td><td class=\"v\">10.96.0.1</td></tr>\n"
        .. "<tr><td class=\"e\">POD_NAMESPACE</td><td class=\"v\">production</td></tr>\n"
        .. "<tr><td class=\"e\">GIT_COMMIT</td><td class=\"v\">7f3c1a92</td></tr>\n"
        .. "<tr><td class=\"e\">PATH</td><td class=\"v\">/usr/local/sbin:/usr/local/bin:/usr/sbin</td></tr>\n"
        .. "<tr><td class=\"e\">LANG</td><td class=\"v\">C.UTF-8</td></tr>\n"
        .. "</table>\n"
        .. "<h2>HTTP Headers Information</h2>\n"
        .. "<table><tr class=\"h\"><th>HTTP Request Header</th><th>Value</th></tr>\n"
        .. "<tr><td class=\"e\">HTTP_HOST</td><td class=\"v\">target.example.com</td></tr>\n"
        .. "<tr><td class=\"e\">HTTP_AUTHORIZATION</td><td class=\"v\">Bearer eyJhbGciOiJIUzI1NiJ9.demo</td></tr>\n"
        .. "<tr><td class=\"e\">HTTP_COOKIE</td><td class=\"v\">PHPSESSID=9k2m4x; remember=1</td></tr>\n"
        .. "<tr><td class=\"e\">HTTP_X_FORWARDED_FOR</td><td class=\"v\">203.0.113.44</td></tr>\n"
        .. "<tr><td class=\"e\">HTTP_X_API_KEY</td><td class=\"v\">ak_live_8f2b1c</td></tr>\n"
        .. "<tr><td class=\"e\">HTTP_USER_AGENT</td><td class=\"v\">Nmap NSE</td></tr>\n"
        .. "</table>\n"
        .. "<h2>PHP License</h2>\n"
        .. "<table><tr><td class=\"e\">This program is free software.</td></tr></table>\n"
        .. "<h2>Zend Engine</h2>\n"
        .. "<table><tr><td class=\"e\">Zend Engine v2.6.0, Copyright (c) 1998-2016 Zend "
        .. "Technologies</td></tr>\n"
        .. "<tr><td class=\"e\">with Xdebug v2.5.5, Copyright (c) 2002-2017, by Derick "
        .. "Rethans</td></tr>\n"
        .. "<tr><td class=\"e\">with the ionCube PHP Loader v10.4.1, Copyright (c) 2002-2020, "
        .. "by ionCube Ltd.</td></tr>\n"
        .. "<tr><td class=\"e\">with imagick 3.4.4 (ImageMagick 6.9.10-23)</td></tr></table>\n"
        .. "</div></body></html>\n"
      add("Content-Type", "text/html; charset=UTF-8")
      add("X-Powered-By", "PHP/5.6.40")
    elseif lpath_target(path) == "/info.php" then
      body = "<html><head><title>phpinfo()</title></head><body>"
        .. "<h1 class=\"p\">PHP Version 8.3.6</h1>"
        .. "<table><tr><td class=\"e\">allow_url_fopen</td><td class=\"v\">Off</td></tr>"
        .. "<tr><td class=\"e\">disable_functions</td>"
        .. "<td class=\"v\">exec,passthru,shell_exec,system,proc_open,popen</td></tr></table>"
        .. "</body></html>"
      add("Content-Type", "text/html")
    else
      body = "<html><head><title>It works</title></head><body><h1>It works</h1></body></html>"
      add("Content-Type", "text/html")
    end
  elseif scenario == "swagger" then
    local lpath = lpath_target(path)
    if lpath == "/swagger-ui.html" then
      body = [[<!DOCTYPE html>
<html><head>
<link rel="stylesheet" type="text/css" href="./swagger-ui.css">
<title>Swagger UI</title>
</head>
<body>
<div id="swagger-ui"></div>
<script src="./swagger-ui-bundle.js"></script>
<script src="./swagger-ui-standalone-preset.js"></script>
<script>
window.onload = function() {
  window.ui = SwaggerUIBundle({
    url: "/v3/api-docs",
    dom_id: '#swagger-ui',
    deepLinking: true
  });
};
</script>
</body></html>]]
      add("Content-Type", "text/html; charset=utf-8")
      add("Server", "nginx/1.24.0")
    elseif lpath == "/swagger-ui-bundle.js" then
      body = "/* SwaggerUIBundle v5.11.0 */\nvar SwaggerUIBundle = {};\n"
      add("Content-Type", "application/javascript")
    elseif lpath == "/v3/api-docs" then
      body = [[{
  "openapi": "3.0.2",
  "info": {
    "title": "Acme Commerce API",
    "version": "2.7.1",
    "description": "Internal commerce platform",
    "contact": { "name": "API Team", "email": "api-team@acme.internal" },
    "license": { "name": "Proprietary" }
  },
  "servers": [
    { "url": "http://10.0.0.5:8080" },
    { "url": "https://staging.api.acme-corp.com" },
    { "url": "https://api.acme-corp.com" }
  ],
  "tags": [ { "name": "users" }, { "name": "payments" }, { "name": "admin" }, { "name": "system" } ],
  "paths": {
    "/api/v1/users": { "get": { "tags": ["users"], "operationId": "listUsers", "security": [ { "BearerAuth": [] } ] } },
    "/api/v1/users/{id}": { "get": { "operationId": "getUser", "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } } ] } },
    "/api/v1/users/{id}/password": { "put": { "operationId": "resetPassword", "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/PasswordUpdate" } } } } } },
    "/api/v1/auth/login": { "post": { "operationId": "login", "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/LoginRequest" } } } } } },
    "/api/v1/auth/token/refresh": { "post": { "operationId": "refreshToken" } },
    "/api/v1/export/orders": { "get": { "operationId": "exportOrders", "parameters": [ { "name": "access_token", "in": "query", "schema": { "type": "string" } } ] } },
    "/api/v1/upload/avatar": { "post": { "operationId": "uploadAvatar" } },
    "/api/v1/admin/users": { "get": { "operationId": "adminListUsers", "security": [ { "ApiKeyAuth": [] } ], "parameters": [ { "name": "api_key", "in": "query", "schema": { "type": "string" } } ] } },
    "/api/v1/admin/config": { "get": { "operationId": "adminReadConfig" } },
    "/api/v1/admin/backup/create": { "post": { "operationId": "createBackup" } },
    "/api/v1/internal/health": { "get": { "operationId": "internalHealth" } },
    "/api/v1/internal/debug/dump": { "get": { "operationId": "debugDump" } },
    "/api/v1/payments/transfer": { "post": { "operationId": "transferFunds", "requestBody": { "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TransferRequest" } } } } } },
    "/api/v1/wallets/{id}/keys": { "get": { "operationId": "walletKeys" } },
    "/api/v1/files/{name}/download": { "get": { "operationId": "downloadFile", "parameters": [ { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } } ] } },
    "/api/v1/git/status": { "get": { "operationId": "gitStatus" } },
    "/api/v1/webhooks": { "post": { "operationId": "registerWebhook" } },
    "/api/v1/setup/wizard": { "get": { "operationId": "setupWizard" } },
    "/api/v1/query": { "post": { "operationId": "rawQuery" } }
  },
  "components": {
    "securitySchemes": {
      "BearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" },
      "ApiKeyAuth": { "type": "apikey", "in": "header", "name": "X-Api-Key" },
      "Oauth2Flow": { "type": "oauth2", "flows": { "authorizationCode": { "authorizationUrl": "https://auth.acme.internal/authorize", "tokenUrl": "http://10.0.0.9:9443/token" } } }
    },
    "schemas": {
      "LoginRequest": { "type": "object", "properties": { "username": { "type": "string" }, "password": { "type": "string", "format": "password" } } },
      "PasswordUpdate": { "type": "object", "properties": { "password": { "type": "string" }, "client_secret": { "type": "string" } } },
      "TransferRequest": { "type": "object", "properties": { "access_token": { "type": "string" }, "amount": { "type": "number" }, "cvv": { "type": "string" } } },
      "InternalRecord": { "type": "object", "properties": { "private_key": { "type": "string" }, "ssn": { "type": "string" }, "signature": { "type": "string" } } }
    }
  },
  "x-internal": true,
  "x-build": "7f3c1a92"
}]]
      add("Content-Type", "application/json")
      add("X-Frame-Options", "SAMEORIGIN")
    elseif lpath == "/openapi.yaml" then
      body = [[swagger: "2.0"
info:
  title: Legacy Billing API
  version: 0.9.3
  description: Billing service exported from an older gateway
  contact:
    name: Billing Team
    email: billing@acme.internal
host: api.legacy-internal.acme-corp.com
basePath: /billing
schemes:
  - http
  - https
securityDefinitions:
  basicAuth:
    type: basic
paths:
  /invoices:
    get:
      operationId: listInvoices
    post:
      operationId: createInvoice
  /invoices/{id}/download:
    get:
      operationId: downloadInvoice
      parameters:
        - name: id
          in: path
          type: string
          required: true
  /backup:
    get:
      operationId: downloadBackup
  /restore:
    post:
      operationId: restoreBackup
  /config:
    get:
      operationId: readConfig]]
      add("Content-Type", "application/yaml")
    elseif lpath == "/swagger-resources" then
      body = [[[{
  "name": "default",
  "location": "/v3/api-docs/default",
  "swaggerVersion": "3.0",
  "scope": "global"
}, {
  "name": "orders",
  "location": "/v3/api-docs/orders",
  "swaggerVersion": "3.0",
  "scope": "global"
}, {
  "name": "admin-api",
  "location": "/v3/api-docs/admin-api",
  "swaggerVersion": "3.0",
  "scope": "global"
}
]
]]
      add("Content-Type", "application/json")
    elseif lpath == "/v3/api-docs/default" then
      body = [[{
  "openapi": "3.0.1",
  "info": { "title": "Default Group", "version": "0.1.0" },
  "paths": {
    "/ping": { "get": { "operationId": "ping" } }
  }
}]]
      add("Content-Type", "application/json")
    elseif lpath == "/v3/api-docs/orders" then
      body = [[{
  "openapi": "3.0.1",
  "info": { "title": "Orders Service", "version": "1.4.0" },
  "servers": [ { "url": "https://orders.internal.corp" } ],
  "paths": {
    "/orders": { "get": { "operationId": "listOrders" }, "post": { "operationId": "createOrder" } },
    "/orders/{id}": { "get": { "operationId": "getOrder" }, "delete": { "operationId": "deleteOrder" } },
    "/orders/{id}/payment": { "post": { "operationId": "payOrder" } },
    "/admin/orders/purge": { "post": { "operationId": "purgeOrders" } }
  },
  "components": {
    "securitySchemes": { "BasicAuth": { "type": "http", "scheme": "basic" } }
  }
}]]
      add("Content-Type", "application/json")
    elseif lpath == "/v3/api-docs/admin-api" then
      body = [[{
  "openapi": "3.0.1",
  "info": { "title": "Admin API", "version": "3.0.0" },
  "paths": {
    "/admin/roles": { "get": { "operationId": "listRoles" } },
    "/admin/audit-logs": { "get": { "operationId": "readAuditLogs" } },
    "/admin/secrets": { "get": { "operationId": "readSecrets" } },
    "/admin/execute/script": { "post": { "operationId": "executeScript" } }
  }
}]]
      add("Content-Type", "application/json")
    elseif lpath == "/redoc" then
      body = [[<!DOCTYPE html>
<html><head><title>ReDoc</title></head>
<body>
<redoc spec="/openapi.yaml"></redoc>
<script src="redoc.min.js"></script>
<script>Redoc.init("/openapi.yaml", { theme: { styling: false } })</script>
</body></html>]]
      add("Content-Type", "text/html")
    elseif lpath == "/graphiql" then
      body = [[<!DOCTYPE html>
<html><head><title>GraphiQL</title></head>
<body>
<div id="graphiql">Loading...</div>
<script src="graphiql.min.js"></script>
<script>GraphiQL.createFetcher({ url: '/graphql' })</script>
</body></html>]]
      add("Content-Type", "text/html")
    else
      body = "<html><head><title>It works</title></head><body><h1>It works</h1></body></html>"
      add("Content-Type", "text/html")
    end
  elseif scenario == "listing" then
    local lpath = real_string.lower(path)
    if lpath == "/backup/" or lpath == "/uploads/" or lpath == "/files/"
      or lpath == "/logs/" or lpath == "/dump/" or lpath == "/dumps/" then
      body = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
        .. "<html>\n <head>\n  <title>Index of " .. path .. "</title>\n </head>\n"
        .. " <body>\n<h1>Index of " .. path .. "</h1>\n"
        .. "  <table>\n"
        .. "   <tr><th><img src=\"/__icon_blank__\" alt=\"Icon \"></th>"
        .. "<th>Name</th><th>Last modified</th><th>Size</th><th>Description</th></tr>\n"
        .. "   <tr><th colspan=\"5\"><hr></th></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/back.gif\" alt=\"[PARENTDIR]\"></td>"
        .. "<td><a href=\"/\">Parent Directory</a></td><td>&nbsp;</td>"
        .. "<td align=\"right\">  - </td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/folder.gif\" alt=\"[DIR]\"></td>"
        .. "<td><a href=\"2023/\">2023/</a></td><td align=\"right\">2023-04-11 09:12  </td>"
        .. "<td align=\"right\">  - </td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/folder.gif\" alt=\"[DIR]\"></td>"
        .. "<td><a href=\"backups/\">backups/</a></td><td align=\"right\">2019-03-02 18:41  </td>"
        .. "<td align=\"right\">  - </td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td>"
        .. "<td><a href=\"db_dump_2024.sql.gz\">db_dump_2024.sql.gz</a></td>"
        .. "<td align=\"right\">2024-06-01 03:15  </td><td align=\"right\"> 48M</td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td>"
        .. "<td><a href=\"id_rsa\">id_rsa</a></td><td align=\"right\">2022-11-08 14:02  </td>"
        .. "<td align=\"right\">3.2K</td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td>"
        .. "<td><a href=\".env\">.env</a></td><td align=\"right\">2024-07-19 11:44  </td>"
        .. "<td align=\"right\">1.4K</td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td>"
        .. "<td><a href=\"wp-config.php.bak\">wp-config.php.bak</a></td>"
        .. "<td align=\"right\">2021-02-14 07:58  </td><td align=\"right\"> 12K</td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/text.gif\" alt=\"[TXT]\"></td>"
        .. "<td><a href=\"access_log\">access_log</a></td><td align=\"right\">2024-08-02 23:59  </td>"
        .. "<td align=\"right\"> 86M</td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/compressed.gif\" alt=\"[   ]\"></td>"
        .. "<td><a href=\"site_backup_2020.tar.gz\">site_backup_2020.tar.gz</a></td>"
        .. "<td align=\"right\">2020-05-30 12:00  </td><td align=\"right\">312M</td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td>"
        .. "<td><a href=\"heapdump.hprof\">heapdump.hprof</a></td>"
        .. "<td align=\"right\">2023-12-01 05:30  </td><td align=\"right\">1.2G</td><td>&nbsp;</td></tr>\n"
        .. "<tr><td valign=\"top\"><img src=\"/icons/image2.gif\" alt=\"[IMG]\"></td>"
        .. "<td><a href=\"passport-scan.jpg\">passport-scan.jpg</a></td>"
        .. "<td align=\"right\">2022-06-21 16:03  </td><td align=\"right\">2.1M</td><td>&nbsp;</td></tr>\n"
        .. "   <tr><th colspan=\"5\"><hr></th></tr>\n</table>\n"
        .. "<address>Apache/2.4.49 (Ubuntu) Server at target.example.com Port 80</address>\n"
        .. "</body></html>\n"
      add("Server", "Apache/2.4.49 (Ubuntu)")
      add("Content-Type", "text/html;charset=UTF-8")
    elseif real_string.find(lpath, "^/nse%-dirlist%-") then
      status = 404
      body = "<html><body>404</body></html>"
    else
      body = "<html><body><h1>It works</h1></body></html>"
      add("Server", "Apache/2.4.49 (Ubuntu)")
      add("X-Powered-By", "PHP/7.4.3")
    end
  end

  return {
    status = status,
    ["status-line"] = "HTTP/1.1 " .. status .. " OK\r\n",
    header = header,
    rawheader = rawheader,
    body = body,
    location = header["location"],
  }
end

mocklib.http = {
  Request = {},
  MAX_REDIRECT_COUNT = 5,
  get = function(host, port, path, options) return mock_http_response(SCENARIO, path, options, nil, "GET") end,
  head = function(host, port, path, options) return mock_http_response(SCENARIO, path, options, nil, "HEAD") end,
  post = function(host, port, path, options, data) return mock_http_response(SCENARIO, path, options, data, "POST") end,
  put = function(host, port, path, options, data) return mock_http_response(SCENARIO, path, options, data, "PUT") end,
  delete = function(host, port, path, options, data) return mock_http_response(SCENARIO, path, options, data, "DELETE") end,
  options = function(host, port, path, opts) return mock_http_response(SCENARIO, path, opts, nil, "OPTIONS") end,
  trace = function(host, port, path, opts) return mock_http_response(SCENARIO, path, opts, nil, "TRACE") end,
  generic_request = function(host, port, method, path) return mock_http_response(SCENARIO, path, nil, nil, method) end,
  request = function(host, port, path, options, data, method) return mock_http_response(SCENARIO, path, options, data, method or "POST") end,
  request_pipeline = function(host, port, requests, options)
    local responses = {}
    for i = 1, #requests do
      responses[i] = mock_http_response(SCENARIO, requests[i].path or "/", options)
    end
    return responses
  end,
  pipeline_add = function(path, options, requests, method)
    requests = requests or {}
    requests[#requests + 1] = { path = path, options = options, method = method or "GET" }
    return requests
  end,
  pipeline = function(host, port, requests, options)
    return mocklib.http.request_pipeline(host, port, requests, options)
  end,
  parse_url = mocklib.url.parse,
  redirect_ok = function(host, port) return true end,
}

SOCKET_LOG = {}

function build_method_response(request)
  local text = tostring(request or "")
  local method, target = real_string.match(text, "^([A-Z]+) ([^ ]+) HTTP/")
  method = method or "GET"
  local marker = real_string.match(text, "X%-NSE%-Method%-Probe: ([^\r\n]+)")
  local function reply(status, reason, headers, body)
    body = body or ""
    local lines = {}
    lines[#lines + 1] = "HTTP/1.1 " .. status .. " " .. reason .. "\r\n"
    lines[#lines + 1] = "Server: nginx/1.24.0\r\n"
    lines[#lines + 1] = "Date: Sat, 19 Sep 2026 10:00:00 GMT\r\n"
    for _, header in ipairs(headers or {}) do
      lines[#lines + 1] = header .. "\r\n"
    end
    lines[#lines + 1] = "Content-Length: " .. #body .. "\r\n"
    lines[#lines + 1] = "Connection: close\r\n"
    lines[#lines + 1] = "\r\n"
    lines[#lines + 1] = body
    return real_table.concat(lines, "")
  end
  if method == "OPTIONS" then
    return reply(204, "No Content", {
      "Allow: GET, HEAD, POST, OPTIONS, TRACE",
      "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Origin: *",
    })
  elseif method == "TRACE" or method == "TRACK" then
    local echoed = method .. " " .. (target or "/") .. " HTTP/1.1\r\n"
    local headers_block = real_string.match(text, "\r\n(.-)\r\n\r\n") or ""
    for line in real_string.gmatch(headers_block, "([^\r\n]+)") do
      echoed = echoed .. line .. "\r\n"
    end
    echoed = echoed .. "X-Forwarded-For: 203.0.113.7\r\n"
    echoed = echoed .. "X-Remote-User: nse-proxy-injected\r\n"
    if marker then
      echoed = echoed .. "X-NSE-Method-Probe: " .. marker .. "\r\n"
    end
    echoed = echoed .. "\r\n"
    return reply(200, "OK", { "Content-Type: message/http" }, echoed)
  elseif method == "PROPFIND" or method == "REPORT" or method == "SEARCH" then
    return reply(207, "Multi-Status", { "Content-Type: application/xml; charset=utf-8", "DAV: 1, 2" },
      '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">'
      .. '<d:response><d:href>' .. (target or "/") .. '</d:href>'
      .. '<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype>'
      .. '</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>'
      .. '</d:multistatus>')
  elseif method == "LOCK" then
    return reply(423, "Locked", { "Content-Type: " .. "text/plain" }, "resource locked")
  elseif method == "PUT" or method == "MKCOL" or method == "DELETE" or method == "PATCH"
    or method == "MOVE" or method == "COPY" or method == "PROPPATCH" or method == "ACL"
    or method == "MERGE" or method == "UPDATE" or method == "LABEL" or method == "CHECKIN"
    or method == "CHECKOUT" or method == "BIND" or method == "REBIND" or method == "UNBIND"
    or method == "PURGE" or method == "MKWORKSPACE" or method == "MKACTIVITY"
    or method == "ORDERPATCH" or method == "UNCHECKOUT" or method == "BASELINE-CONTROL"
    or method == "VERSION-CONTROL" or method == "BMOVE" or method == "BDELETE"
    or method == "BPROPPATCH" then
    return reply(405, "Method Not Allowed", { "Allow: GET, HEAD, POST, OPTIONS" },
      "<html><head><title>405 Not Allowed</title></head><body><center><h1>405 Not Allowed</h1></center>"
      .. "<hr><center>nginx/1.24.0</center></body></html>")
  elseif method == "CONNECT" then
    return reply(403, "Forbidden", {}, "connect refused")
  elseif method == "GET" then
    return reply(200, "OK", { "Content-Type: text/html" }, "<html><body>ok</body></html>")
  elseif method == "HEAD" then
    return reply(200, "OK", { "Content-Type: text/html", "Content-Length: 27" })
  elseif method == "POST" then
    return reply(200, "OK", { "Content-Type: text/html" }, "<html><body>posted</body></html>")
  end
  return reply(501, "Not Implemented", {}, "<html><body>501 Not Implemented</body></html>")
end


local function denc(name)
  local out = ""
  for label in real_string.gmatch(tostring(name or ""), "[^%.]+") do
    out = out .. real_string.char(#label) .. label
  end
  return out .. real_string.char(0)
end

local function du16(v) return real_string.char(real_math.floor(v / 256) % 256, v % 256) end
local function du32(v)
  return real_string.char(real_math.floor(v / 16777216) % 256, real_math.floor(v / 65536) % 256,
    real_math.floor(v / 256) % 256, v % 256)
end

local function d4(ip)
  local a, b, c, d = real_string.match(ip, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return "" end
  return real_string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end

local function d6(ip)
  local s = tostring(ip)
  local halves = {}
  for half in real_string.gmatch(s, "[^:]+") do halves[#halves + 1] = half end
  local groups = {}
  if #halves < 8 then
    local l, r = real_string.find(s, "::")
    local left = {}
    if l > 1 then for h in real_string.gmatch(real_string.sub(s, 1, l - 1), "[^:]+") do left[#left + 1] = h end end
    local right = {}
    if r < #s then for h in real_string.gmatch(real_string.sub(s, r + 1), "[^:]+") do right[#right + 1] = h end end
    local mid = real_string.rep("0", 8 - #left - #right)
    for _, h in ipairs(left) do groups[#groups + 1] = h end
    for i = 1, #mid do groups[#groups + 1] = real_string.sub(mid, i, i) end
    for _, h in ipairs(right) do groups[#groups + 1] = h end
  else
    for _, h in ipairs(halves) do groups[#groups + 1] = h end
  end
  local out = ""
  for i = 1, 8 do
    out = out .. du16(tonumber(groups[i], 16))
  end
  return out
end

local function dtxt(text)
  if #text > 255 then text = real_string.sub(text, 1, 255) end
  return real_string.char(#text) .. text
end

local function dsoa(mname, rname, serial, refresh, retry, expire, minimum)
  return denc(mname) .. denc(rname) .. du32(serial) .. du32(refresh) .. du32(retry)
    .. du32(expire) .. du32(minimum)
end

local function dmx(pref, exch) return du16(pref) .. denc(exch) end
local function dsrv(prio, weight, port, target)
  return du16(prio) .. du16(weight) .. du16(port) .. denc(target)
end

local function drec(name, rtype, ttl, rdata)
  return denc(name) .. du16(rtype) .. du16(1) .. du32(ttl) .. du16(#rdata) .. rdata
end

local function dbuild(id, qname, qtype, rcode, answers, authority, tc)
  local flags = 0x8000 + (rcode or 0)
  if tc then flags = flags + 0x0200 end
  local header = du16(id) .. du16(flags) .. du16(1)
    .. du16(#(answers or {})) .. du16(#(authority or {})) .. du16(0)
  local body = header .. denc(qname) .. du16(qtype) .. du16(1)
  for _, a in ipairs(answers or {}) do body = body .. drec(a[1], a[2], a[3] or 300, a[4]) end
  for _, a in ipairs(authority or {}) do body = body .. drec(a[1], a[2], a[3] or 300, a[4]) end
  return body
end

local mock_dns_cache = {}

local SNOOP_DOMAINS = {
  ["example.org"] = true, ["example.net"] = true, ["example.edu"] = true,
  ["cloudflare.com"] = true, ["google.com"] = true, ["apple.com"] = true,
  ["wikipedia.org"] = true, ["amazon.com"] = true, ["microsoft.com"] = true,
}

local function dquery(data)
  if type(data) ~= "string" or #data < 12 then return nil end
  local id = data:byte(1) * 256 + data:byte(2)
  local pos = 13
  local labels = {}
  while pos <= #data do
    local len = data:byte(pos)
    if len == 0 then pos = pos + 1 break end
    table.insert(labels, real_string.sub(data, pos + 1, pos + len))
    pos = pos + len + 1
  end
  if pos + 1 > #data then return nil end
  local qtype = data:byte(pos) * 256 + data:byte(pos + 1)
  return { id = id, qname = real_string.lower(table.concat(labels, ".")), qtype = qtype }
end

local DNS_APEX = "target.example.com"
local DNS_SOA = { DNS_APEX, 6, 300,
  dsoa("ns1." .. DNS_APEX, "hostmaster." .. DNS_APEX, 2026092101, 7200, 3600, 1209600, 300) }

local B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

local function b64url_decode(text)
  local reverse = {}
  for i = 1, #B64URL_ALPHABET do
    reverse[real_string.sub(B64URL_ALPHABET, i, i)] = i - 1
  end
  local clean = real_string.gsub(real_string.gsub(tostring(text or ""), "=", ""), "[^A-Za-z0-9%-_]", "")
  if #clean == 0 then
    return nil
  end
  local out = {}
  local i = 1
  while i + 3 <= #clean do
    local a = reverse[real_string.sub(clean, i, i)] or 0
    local b = reverse[real_string.sub(clean, i + 1, i + 1)] or 0
    local c = reverse[real_string.sub(clean, i + 2, i + 2)] or 0
    local d = reverse[real_string.sub(clean, i + 3, i + 3)] or 0
    local n = a * 262144 + b * 4096 + c * 64 + d
    out[#out + 1] = real_string.char(math.floor(n / 65536) % 256)
    out[#out + 1] = real_string.char(math.floor(n / 256) % 256)
    out[#out + 1] = real_string.char(n % 256)
    i = i + 4
  end
  local rem = #clean - i + 1
  if rem == 2 then
    local a = reverse[real_string.sub(clean, i, i)] or 0
    local b = reverse[real_string.sub(clean, i + 1, i + 1)] or 0
    local n = a * 64 + b
    out[#out + 1] = real_string.char(math.floor(n / 256) % 256)
  elseif rem == 3 then
    local a = reverse[real_string.sub(clean, i, i)] or 0
    local b = reverse[real_string.sub(clean, i + 1, i + 1)] or 0
    local c = reverse[real_string.sub(clean, i + 2, i + 2)] or 0
    local n = a * 4096 + b * 64 + c
    out[#out + 1] = real_string.char(math.floor(n / 65536) % 256)
    out[#out + 1] = real_string.char(math.floor(n / 256) % 256)
    out[#out + 1] = real_string.char(n % 256)
  end
  return table.concat(out)
end

local function is_base64url(s)
  return s ~= nil and #s >= 32
    and real_string.find(s, "%.", 1, true) == nil
    and real_string.match(s, "^[A-Za-z0-9%-_]+$") ~= nil
end

function doh_dns_answer(query)
  if is_base64url(query) then
    local raw = b64url_decode(query)
    local q = raw and dquery(raw) or nil
    if q and q.qname ~= "" then
      if q.qname == "example.com" or real_string.find(q.qname, "%.example%.com$", 1) then
        if q.qtype == 1 or q.qtype == 255 then
          return dbuild(q.id, q.qname, q.qtype, 0,
            { { q.qname, 1, 300, d4("192.0.2.55") } }, {}, false)
        end
        return dbuild(q.id, q.qname, q.qtype, 0, {}, {}, false)
      end
      return dbuild(q.id, q.qname, q.qtype, 3, {}, {}, false)
    end
  end
  if query and (query == "example.com" or real_string.find(query, "%.example%.com$", 1)) then
    return dbuild(0, query, 1, 0,
      { { query, 1, 300, d4("192.0.2.55") } }, {}, false)
  end
  return dbuild(0, query or "dns-query", 1, 0, {}, {}, false)
end

local function dns_zone_records()
  local apex = DNS_APEX
  local recs = {}
  table.insert(recs, DNS_SOA)
  table.insert(recs, { "ns1." .. apex, 2, 3600, denc("ns1." .. apex) })
  table.insert(recs, { "ns2." .. apex, 2, 3600, denc("ns2." .. apex) })
  table.insert(recs, { "ns3.dns-hq.internal", 2, 3600, denc("ns3.dns-hq.internal") })
  table.insert(recs, { apex, 1, 300, d4("203.0.113.10") })
  table.insert(recs, { apex, 28, 300, d6("2001:db8::10") })
  table.insert(recs, { apex, 15, 3600, dmx(10, "mail1." .. apex) })
  table.insert(recs, { apex, 15, 3600, dmx(20, "mail2." .. apex) })
  table.insert(recs, { apex, 16, 3600, dtxt("v=spf1 include:_spf." .. apex .. " ~all") })
  table.insert(recs, { "_dmarc." .. apex, 16, 3600,
    dtxt("v=DMARC1; p=none; rua=mailto:dmarc@" .. apex) })
  table.insert(recs, { "www." .. apex, 5, 300, denc(apex) })
  table.insert(recs, { "mail1." .. apex, 1, 300, d4("203.0.113.11") })
  table.insert(recs, { "mail2." .. apex, 1, 300, d4("203.0.113.12") })
  table.insert(recs, { "db1." .. apex, 1, 300, d4("10.10.10.5") })
  table.insert(recs, { "internal-api." .. apex, 1, 300, d4("10.10.20.7") })
  table.insert(recs, { "vpn." .. apex, 1, 300, d4("192.168.8.1") })
  table.insert(recs, { "lost-blog." .. apex, 5, 3600, denc("abandoned-blogs.customdomains.example") })
  table.insert(recs, { "old-shop." .. apex, 5, 3600, denc("myshop.myshopify.com") })
  table.insert(recs, { "old-wiki." .. apex, 5, 3600, denc("mywiki.gitlab.io") })
  table.insert(recs, { "cdn." .. apex, 5, 3600, denc("bunny.net") })
  table.insert(recs, { "old-app." .. apex, 5, 3600, denc("legacyapp.herokuapp.com") })
  table.insert(recs, { "static." .. apex, 5, 3600, denc("cdn-origin.bunny.net") })
  table.insert(recs, { "_sip._tcp." .. apex, 25, 300, dsrv(20, 5, 5060, "sip1." .. apex) })
  table.insert(recs, { "_xmpp-client._tcp." .. apex, 25, 300, dsrv(5, 0, 5222, "xmpp1." .. apex) })
  table.insert(recs, { "_autodiscover._tcp." .. apex, 25, 300, dsrv(0, 0, 443, "autodiscover." .. apex) })
  table.insert(recs, { "_ldap._tcp." .. apex, 25, 300, dsrv(0, 0, 389, "ldap.dcs.internal.corp") })
  table.insert(recs, { "_caldav._tcp." .. apex, 25, 300, dsrv(0, 0, 443, "caldav." .. apex) })
  table.insert(recs, { "_imaps._tcp." .. apex, 25, 300, dsrv(0, 0, 993, "mail1." .. apex) })
  table.insert(recs, { "_deploy." .. apex, 16, 3600, dtxt("deploy-token: glpat-xyz123secret") })
  table.insert(recs, { "_internal-note." .. apex, 16, 3600,
    dtxt("staging db password = StagingP@ss2026") })
  return recs
end

local function dns_axfr_reply(q)
  local recs = dns_zone_records()
  local pkts = ""
  local function pkt(records)
    local body = dbuild(q.id, q.qname, 252, 0, records, {}, false)
    return du16(#body) .. body
  end
  pkts = pkts .. pkt({ DNS_SOA })
  local middle = {}
  for _, r in ipairs(recs) do
    if r ~= DNS_SOA then
      table.insert(middle, r)
    end
  end
  local chunk = {}
  local i = 1
  while i <= #middle do
    chunk = {}
    for j = i, real_math.min(i + 9, #middle) do table.insert(chunk, middle[j]) end
    pkts = pkts .. pkt(chunk)
    i = i + 10
  end
  pkts = pkts .. pkt({ DNS_SOA })
  return pkts
end

local function dns_ixfr_reply(q)
  local body1 = dbuild(q.id, q.qname, 253, 0,
    { DNS_SOA,
      { "db1." .. DNS_APEX, 1, 300, d4("10.10.10.5") },
      { "retired." .. DNS_APEX, 1, 300, d4("10.10.10.9") } }, {}, false)
  local body2 = dbuild(q.id, q.qname, 253, 0,
    { DNS_SOA,
      { "db1." .. DNS_APEX, 1, 300, d4("10.10.10.6") },
      { "newnode." .. DNS_APEX, 1, 300, d4("10.10.10.20") },
      DNS_SOA }, {}, false)
  return du16(#body1) .. body1 .. du16(#body2) .. body2
end

local function dns_mock_reply(scenario, data, port, proto)
  local hardened = (scenario == "dns-hardened")
  if type(data) == "string" and #data >= 4 and port == 443
    and real_string.sub(data, 1, 2) == real_string.char(0x19, 0x13) then
    if real_string.sub(data, 3, 4) == real_string.char(0x00, 0x00) then
      if hardened then return "__DNSMOCK_DROP__" end
      local server = real_string.char(0x79, 0x6f, 0x33, 0x9a)
      return server .. real_string.char(0x00, 0x00) .. real_string.rep("z", 27)
    end
    return "__DNSMOCK_DROP__"
  end
  local q = dquery(data)
  if not q then return nil end
  local apex = DNS_APEX
  local domain = q.qname
  local qtype = q.qtype
  if scenario ~= "dns" and scenario ~= "dns-hardened" then
    return nil
  end

  if qtype == 252 then
    if hardened then
      local resp = dbuild(q.id, q.qname, 252, 5, {}, {}, false)
      if proto == "tcp" then
        return du16(#resp) .. resp
      end
      return resp
    end
    if proto == "tcp" then
      return dns_axfr_reply(q)
    end
    return dbuild(q.id, q.qname, 252, 0, { DNS_SOA }, { DNS_SOA }, true)
  end
  if qtype == 253 then
    if hardened then
      local resp = dbuild(q.id, q.qname, 253, 5, {}, {}, false)
      if proto == "tcp" then
        return du16(#resp) .. resp
      end
      return resp
    end
    if proto == "tcp" then
      return dns_ixfr_reply(q)
    end
    return dbuild(q.id, q.qname, 253, 5, {}, {}, false)
  end

  if not hardened and domain == apex and qtype == 1 then
    mock_dns_cache["__apex__"] = (mock_dns_cache["__apex__"] or 0) + 1
    if mock_dns_cache["__apex__"] >= 2 then
      return dbuild(q.id, domain, 1, 0,
        { { apex, 1, 1, d4("203.0.113.10") } }, {}, false)
    end
  end

  if domain == apex then
    if qtype == 33 then
      if hardened then
        local digest = real_string.rep("d", 32)
        return dbuild(q.id, domain, 33, 0,
          { { apex, 33, 3600, du16(32253) .. real_string.char(8, 2) .. digest } }, {}, false)
      end
      return dbuild(q.id, domain, 33, 3, {}, {}, false)
    end
    if qtype == 46 then
      if hardened then
        local key_data = real_string.rep("k", 64)
        return dbuild(q.id, domain, 46, 0,
          { { apex, 46, 300, du16(257) .. real_string.char(3, 13) .. key_data },
            { apex, 46, 300, du16(256) .. real_string.char(3, 13) .. real_string.rep("z", 64) } }, {}, false)
      end
      return dbuild(q.id, domain, 46, 3, {}, {}, false)
    end
    if qtype == 43 then
      if hardened then
        local rr = {
          type_covered = 6, algorithm = 13, labels = 3, sig_ttl = 300,
          expiration = 1798780800, inception = 1788192000, key_tag = 32253,
          signer = apex,
        }
        local rdata = du16(rr.type_covered) .. real_string.char(rr.algorithm, rr.labels)
          .. du32(rr.sig_ttl) .. du32(rr.expiration) .. du32(rr.inception)
          .. du16(rr.key_tag) .. denc(rr.signer) .. real_string.rep("s", 80)
        return dbuild(q.id, domain, 43, 0,
          { { apex, 43, 300, rdata } }, {}, false)
      end
      return dbuild(q.id, domain, 43, 3, {}, {}, false)
    end
    if qtype == 48 then
      if hardened then
        local salt = real_string.rep("9", 4)
        local rdata = real_string.char(1, 0) .. du16(0) .. real_string.char(#salt) .. salt
          .. real_string.rep("h", 20) .. real_string.char(0, 0)
        return dbuild(q.id, domain, 48, 0,
          { { apex, 48, 300, rdata } }, {}, false)
      end
      return dbuild(q.id, domain, 48, 3, {}, {}, false)
    end
    if qtype == 6 or qtype == 255 then
      if qtype == 255 and not hardened then
        local recs = dns_zone_records()
        local any_recs = {}
        local seen_types = {}
        for _, r in ipairs(recs) do
          if not seen_types[r[2]] then
            seen_types[r[2]] = true
            table.insert(any_recs, r)
          end
        end
        return dbuild(q.id, domain, 255, 0, any_recs, { DNS_SOA }, false)
      end
      return dbuild(q.id, domain, qtype, 0, { DNS_SOA }, {}, false)
    end
    if qtype == 2 then
      if hardened then
        return dbuild(q.id, domain, 2, 0,
          { { "ns1." .. apex, 2, 3600, denc("ns1." .. apex) },
            { "ns2." .. apex, 2, 3600, denc("ns2." .. apex) } }, {}, false)
      end
      return dbuild(q.id, domain, 2, 0,
        { { "ns1." .. apex, 2, 3600, denc("ns1." .. apex) },
          { "ns2." .. apex, 2, 3600, denc("ns2." .. apex) },
          { "ns3.dns-hq.internal", 2, 3600, denc("ns3.dns-hq.internal") } }, {}, false)
    end
    if qtype == 1 then
      return dbuild(q.id, domain, 1, 0,
        { { apex, 1, 300, d4("203.0.113.10") } }, {}, false)
    end
    if qtype == 28 then
      return dbuild(q.id, domain, 28, 0,
        { { apex, 28, 300, d6("2001:db8::10") } }, {}, false)
    end
    if qtype == 15 then
      return dbuild(q.id, domain, 15, 0,
        { { apex, 15, 3600, dmx(10, "mail1." .. apex) },
          { apex, 15, 3600, dmx(20, "mail2." .. apex) } }, {}, false)
    end
    if qtype == 16 then
      if hardened then
        return dbuild(q.id, domain, 16, 0,
          { { apex, 16, 3600, dtxt("v=spf1 include:_spf." .. apex .. " -all") } }, {}, false)
      end
      return dbuild(q.id, domain, 16, 0,
        { { apex, 16, 3600, dtxt("v=spf1 include:_spf." .. apex .. " ~all") } }, {}, false)
    end
    if qtype == 46 or qtype == 33 or qtype == 43 or qtype == 45 or qtype == 48 then
      return dbuild(q.id, domain, qtype, 0, {}, { DNS_SOA }, false)
    end
    return dbuild(q.id, domain, qtype, 0, {}, { DNS_SOA }, false)
  end

  if domain == "_dmarc." .. apex and qtype == 16 then
    if hardened then
      return dbuild(q.id, domain, 16, 0,
        { { domain, 16, 3600, dtxt("v=DMARC1; p=reject; rua=mailto:dmarc@" .. apex) } }, {}, false)
    end
    return dbuild(q.id, domain, 16, 0,
      { { domain, 16, 3600, dtxt("v=DMARC1; p=none; rua=mailto:dmarc@" .. apex) } }, {}, false)
  end

  if real_string.find(domain, "^www%." .. real_string.gsub(apex, "%.", "%%.") .. "$", 1) then
    if qtype == 1 or qtype == 5 then
      return dbuild(q.id, domain, qtype, 0,
        { { domain, 5, 300, denc(apex) },
          { apex, 1, 300, d4("203.0.113.10") } }, {}, false)
    end
    return dbuild(q.id, domain, qtype, 0, { { domain, 5, 300, denc(apex) } }, {}, false)
  end


  local srv_map = {
    ["_autodiscover._tcp." .. apex] = { 0, 0, 443, "autodiscover." .. apex },
  }
  if not hardened then
    srv_map["_sip._tcp." .. apex] = { 20, 5, 5060, "sip1." .. apex }
    srv_map["_xmpp-client._tcp." .. apex] = { 5, 0, 5222, "xmpp1." .. apex }
    srv_map["_ldap._tcp." .. apex] = { 0, 0, 389, "ldap.dcs.internal.corp" }
    srv_map["_caldav._tcp." .. apex] = { 0, 0, 443, "caldav." .. apex }
    srv_map["_imaps._tcp." .. apex] = { 0, 0, 993, "mail1." .. apex }
    srv_map["_sipfederation._tcp." .. apex] = { 10, 0, 5061, "federation.sip1." .. apex }
    srv_map["_mysql._tcp." .. apex] = { 0, 0, 3306, "db1." .. apex }
  end
  local srv = srv_map[domain]
  if srv and qtype == 25 then
    return dbuild(q.id, domain, 25, 0,
      { { domain, 25, 300, dsrv(srv[1], srv[2], srv[3], srv[4]) } }, {}, false)
  end

  local fixed_hosts = {
    ["ns1." .. apex] = "203.0.113.53",
    ["ns2." .. apex] = "203.0.113.54",
    ["mail1." .. apex] = "203.0.113.11",
    ["mail2." .. apex] = "203.0.113.12",
    ["db1." .. apex] = "10.10.10.5",
    ["internal-api." .. apex] = "10.10.20.7",
    ["vpn." .. apex] = "192.168.8.1",
    ["sip1." .. apex] = "203.0.113.31",
    ["xmpp1." .. apex] = "203.0.113.32",
    ["autodiscover." .. apex] = "203.0.113.33",
    ["caldav." .. apex] = "203.0.113.34",
  }
  if fixed_hosts[domain] and (qtype == 1 or qtype == 255) then
    return dbuild(q.id, domain, qtype, 0,
      { { domain, 1, 300, d4(fixed_hosts[domain]) } }, {}, false)
  end

  local ra, rb, rc, rd = real_string.match(domain, "^(%d+)%.(%d+)%.(%d+)%.(%d+)%.in%-addr%.arpa$")
  if ra then
    local a, b, c, d = ra, rb, rc, rd
    if a == "10" and b == "113" and c == "0" and d == "203" then
      return dbuild(q.id, domain, 12, 0,
        { { domain, 12, 300, denc(apex) } }, {}, false)
    end
    if a == "1" and b == "1" and c == "168" and d == "192" then
      if hardened then
        return dbuild(q.id, domain, 12, 3, {}, {}, false)
      end
      return dbuild(q.id, domain, 12, 0,
        { { domain, 12, 300, denc("workstation-01.internal.lan") } }, {}, false)
    end
    if a == "11" and b == "113" and c == "0" and d == "203" then
      if hardened then
        return dbuild(q.id, domain, 12, 3, {}, {}, false)
      end
      return dbuild(q.id, domain, 12, 0,
        { { domain, 12, 300, denc("mail1." .. apex) } }, {}, false)
    end
    if a == "12" and b == "113" and c == "0" and d == "203" then
      if hardened then
        return dbuild(q.id, domain, 12, 3, {}, {}, false)
      end
      return dbuild(q.id, domain, 12, 0,
        { { domain, 12, 300, denc("mailhost-backup.internal.corp") } }, {}, false)
    end
    return dbuild(q.id, domain, 12, 3, {}, {}, false)
  end

  if real_string.find(domain, "^cached%.", 1, true) then
    if real_string.find(domain, "%." .. real_string.gsub(apex, "%.", "%%.") .. "$", 1) then
      return dbuild(q.id, domain, qtype, 0,
        { { real_string.gsub(domain, "^cached%.", "cache-hit%."), 1, 1, d4("198.51.100.77") } }, {}, false)
    end
  end

  if not hardened then
    if domain == "internal.corp" or domain == "internal.corp." then
      return dbuild(q.id, domain, qtype, 0,
        { { domain, 1, 300, d4("10.99.99.1") },
          { domain, 2, 3600, denc("ns-internal.corp") } }, {}, false)
    end
  end

  local extra_txt = {}
  if hardened then
    extra_txt["_spf." .. apex] = "v=spf1 ip4:203.0.113.0/24 -all"
    extra_txt["default._domainkey." .. apex] =
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfakekeymaterial0123456789"
    extra_txt["google._domainkey." .. apex] =
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgooglefakekey9876543210"
  else
    extra_txt["_spf." .. apex] = "v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.10 -all"
    extra_txt["default._domainkey." .. apex] =
      "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdefaultkeymaterial00000000"
    extra_txt["selector1._domainkey." .. apex] = "v=DKIM1; k=rsa; p="
  end
  if extra_txt[domain] and qtype == 16 then
    return dbuild(q.id, domain, 16, 0,
      { { domain, 16, 3600, dtxt(extra_txt[domain]) } }, {}, false)
  end

  local takeover_cnames = {
    ["lost-blog." .. apex] = "abandoned-blogs.customdomains.example",
    ["old-shop." .. apex] = "myshop.myshopify.com",
    ["old-wiki." .. apex] = "mywiki.gitlab.io",
    ["old-app." .. apex] = "legacyapp.herokuapp.com",
    ["cdn." .. apex] = "bunny.net",
    ["static." .. apex] = "cdn-origin.bunny.net",
  }
  local take_target = takeover_cnames[domain]
  if not hardened and take_target and (qtype == 5 or qtype == 1 or qtype == 255) then
    return dbuild(q.id, domain, qtype, 0,
      { { domain, 5, 3600, denc(take_target) } }, {}, false)
  end

  if real_string.find(domain, "%." .. real_string.gsub(apex, "%.", "%%.") .. "$", 1) then
    if hardened then
      return dbuild(q.id, domain, qtype, 3, {}, { DNS_SOA }, false)
    end
    if qtype == 1 or qtype == 255 then
      return dbuild(q.id, domain, qtype, 0,
        { { domain, 1, 300, d4("203.0.113.99") } }, {}, false)
    end
    if qtype == 28 then
      return dbuild(q.id, domain, 28, 0,
        { { domain, 28, 300, d6("2001:db8::99") } }, {}, false)
    end
    if qtype == 2 then
      return dbuild(q.id, domain, 2, 0,
        { { domain, 2, 3600, denc("ns1." .. apex) },
          { domain, 2, 3600, denc("ns2." .. apex) },
          { domain, 2, 3600, denc("ns3.dns-hq.internal") } }, {}, false)
    end
    if qtype == 15 then
      return dbuild(q.id, domain, 15, 0,
        { { domain, 15, 3600, dmx(10, "mail1." .. apex) },
          { domain, 15, 3600, dmx(20, "mail2." .. apex) } }, {}, false)
    end
    if qtype == 5 then
      return dbuild(q.id, domain, 5, 0,
        { { domain, 5, 300, denc("wildcard." .. apex) } }, {}, false)
    end
    if qtype == 12 then
      return dbuild(q.id, domain, 12, 3, {}, { DNS_SOA }, false)
    end
    return dbuild(q.id, domain, qtype, 0, {}, { DNS_SOA }, false)
  end

  if not hardened and (domain == "example.org" or domain == "example.org.") then
    return dbuild(q.id, domain, qtype, 0,
      { { domain, 1, 300, d4("192.0.2.44") } }, {}, false)
  end

  local third_party_ips = {
    ["myshop.myshopify.com"] = "203.0.113.50",
    ["bunny.net"] = "198.41.0.1",
    ["cdn-origin.bunny.net"] = nil,
  }
  if not hardened and third_party_ips[domain] and (qtype == 1 or qtype == 255) then
    return dbuild(q.id, domain, qtype, 0,
      { { domain, 1, 300, d4(third_party_ips[domain]) } }, {}, false)
  end

  if not hardened and SNOOP_DOMAINS[domain] and (qtype == 1 or qtype == 255) then
    mock_dns_cache[domain] = (mock_dns_cache[domain] or 0) + 1
    local hits = mock_dns_cache[domain]
    if hits >= 2 then
      return dbuild(q.id, domain, qtype, 0,
        { { domain, 1, 1, d4("192.0.2.44") } }, {}, false)
    end
    return dbuild(q.id, domain, qtype, 0,
      { { domain, 1, 300, d4("192.0.2.44") } }, {}, false)
  end

  return dbuild(q.id, domain, qtype, 3, {}, { DNS_SOA }, false)
end


local function smb_u16(v) return string.char(v % 256, math.floor(v / 256) % 256) end
local function smb_u32(v) return string.char(v % 256, math.floor(v / 256) % 256, math.floor(v / 65536) % 256, math.floor(v / 16777216) % 256) end
local function smb_u64(v) return smb_u32(v % 4294967296) .. smb_u32(math.floor(v / 4294967296) % 4294967296) end
local function smbb(s, n) return s:byte(n + 1) or 0 end
local function smb16(s, n) return smbb(s, n) + smbb(s, n + 1) * 256 end
local function smb32(s, n) return smbb(s, n) + smbb(s, n + 1) * 256 + smbb(s, n + 2) * 65536 + smbb(s, n + 3) * 16777216 end

local function smb_s1_header(cmd, status, flags, mid)
  return string.char(0xff, 0x53, 0x4d, 0x42) .. string.char(cmd)
    .. smb_u16(status or 0) .. string.char(flags or 0x51) .. smb_u16(0)
    .. smb_u16(0x1f0) .. smb_u32(mid or 0) .. smb_u16(0) .. smb_u16(0)
    .. smb_u32(0) .. smb_u16(0) .. smb_u32(0)
end

local function smb_s2_header(cmd, status, ext_flags, mid)
  return string.char(0xfe, 0x53, 0x4d, 0x42)
    .. smb_u16(112)
    .. string.char(0, 0)
    .. smb_u32(status or 0)
    .. smb_u32(1)
    .. smb_u16(cmd)
    .. smb_u16(1)
    .. smb_u32(mid or 0) .. smb_u32(0)
    .. smb_u16(0x0800)
    .. smb_u16(0xffff)
    .. smb_u16(0)
    .. smb_u32(0) .. smb_u32(0)
    .. smb_u32(0) .. smb_u32(0)
    .. string.rep("\0", 16)
    .. smb_u16(0) .. smb_u16(0)
    .. smb_u32(0x00000003) .. smb_u32(ext_flags or 0)
    .. string.rep("\0", 28)
end

local function smb_ascii_to_utf16(text)
  local out = {}
  for i = 1, #text do
    out[#out + 1] = text:sub(i, i) .. string.char(0)
  end
  return table.concat(out)
end

local function smb_ntlm_challenge(challenge_bytes, flags, target_name)
  local tn = smb_ascii_to_utf16(target_name or "")
  local fl = flags or 0x1b0201
  local head = "NTLMSSP\0"
    .. string.char(0x02, 0, 0, 0)
    .. smb_u16(#tn) .. smb_u16(#tn) .. smb_u32(48)
    .. smb_u32(fl)
  local body = challenge_bytes
    .. string.rep("\0", 8)
    .. smb_u16(0) .. smb_u16(0) .. smb_u32(0)
    .. tn
  return head .. body
end

local function smb_negotiate_s1_reply(offered, force_fail)
  local idx = 0xffff
  if not force_fail then
    for i, d in ipairs(offered) do
      if d == "NT LM 0.12" then
        idx = i - 1
        break
      end
    end
  end
  local status = force_fail and 0x0005 or 0x0000
  local params = string.char(0x01, 0)
    .. smb_u32(0x00028813)
    .. smb_u16(65536) .. smb_u16(50)
    .. smb_u32(64432) .. smb_u32(64432)
    .. smb_u16(0) .. smb_u32(0)
    .. smb_u16(idx)
    .. "Windows Server 2019 17763\0Windows Server\0NTFS\0"
  return smb_s1_header(0x02, status, 0x51) .. params
end

local function smb_negotiate_s2_reply(chosen_code, sec_flags)
  local sig = "NTLMSSP\0"
  local params = smb_u16(58)
    .. smb_u16(170) .. smb_u16(#sig)
    .. smb_u16(chosen_code)
    .. smb_u16(0)
    .. string.rep("\0", 16)
    .. smb_u32(0x00000003)
    .. smb_u32(16777216)
    .. smb_u32(1048576)
    .. smb_u32(1048576)
    .. smb_u64(132000000000000000)
    .. smb_u64(132000000000000000)
    .. sig
  return smb_s2_header(0x0001, 0, sec_flags or 0) .. params
end

local function smb_s1_session_setup_reply(status, action, blob)
  if status and status > 0 then
    return smb_s1_header(0x0f, status, 0x51)
  end
  local b = blob or ""
  local params = smb_u16(action or 0)
    .. string.char(#b) .. smb_u16(0)
    .. b
  return smb_s1_header(0x0f, 0, 0x51) .. params
end

local function smb_s1_tree_connect_reply(status, service, access, path, extra)
  if status and status > 0 then
    return smb_s1_header(0x75, status, 0x51) .. (extra or "")
  end
  local p = path or ""
  local params = string.char(0xff) .. smb_u16(0) .. smb_u16(0)
    .. string.char(service or 1, 0, 0, 0)
    .. smb_u32(access or 0x00000001)
    .. smb_u16(#p)
    .. p .. "\0"
  return smb_s1_header(0x75, 0, 0x51) .. params
end

local function smb_dfs_referral()
  local s1 = "file01.corp.example.com"
  local s2 = "file02.corp.example.com"
  local c1 = "\\dfsroot"
  local c2 = "\\dfsroot"
  local s1o, s2o, c1o, c2o = 72, 72 + #s1 + 1, 0, 0
  s2o = 72 + #s1 + 1
  c1o = s2o + #s2 + 1
  c2o = c1o + #c1 + 1
  local total = c2o + #c2 + 1
  local header = smb_u32(total) .. smb_u32(0x00000000) .. smb_u32(0x00000001)
    .. smb_u16(2) .. smb_u16(0x0001)
    .. smb_u16(4) .. smb_u16(64) .. smb_u16(0) .. smb_u16(72)
  local function resp(i, so, ssz, co, csz)
    return smb_u16(64 + i * 4) .. smb_u16(4) .. smb_u32(0)
      .. smb_u16(so) .. smb_u16(ssz)
      .. smb_u16(co) .. smb_u16(csz)
      .. smb_u16(0) .. smb_u16(0)
  end
  local paths = smb_u16(72) .. smb_u16(#s1) .. smb_u16(s2o) .. smb_u16(#s2)
  local body = header .. resp(0, s1o, #s1, c1o, #c1) .. resp(1, s2o, #s2, c2o, #c2) .. paths
    .. s1 .. "\0" .. s2 .. "\0" .. c1 .. "\0" .. c2 .. "\0"
  local extra = smb_u16(#body) .. smb_u16(0) .. smb_u16(0) .. smb_u16(0) .. body
  return extra
end

local function smb_parse_s1_dialects(data)
  local offered = {}
  local count = smb16(data, 32)
  local pos = 34
  for i = 1, count do
    local l = smbb(data, pos)
    table.insert(offered, real_string.sub(data, pos + 2, pos + 1 + l))
    pos = pos + 1 + l
  end
  return offered
end

local function smb_ntlm_auth_user(blob)
  if real_string.sub(blob, 1, 7) ~= "NTLMSSP" or #blob < 64 then
    return "", ""
  end
  local ulen = smb16(blob, 36)
  local uoff = smb32(blob, 40)
  local user = real_string.sub(blob, uoff + 1, uoff + ulen)
  local uname = {}
  for i = 1, #user, 2 do
    table.insert(uname, real_string.char(user:byte(i)))
  end
  local dlen = smb16(blob, 28)
  local doff = smb32(blob, 32)
  local domraw = real_string.sub(blob, doff + 1, doff + dlen)
  local dom = {}
  for i = 1, #domraw, 2 do
    table.insert(dom, real_string.char(domraw:byte(i)))
  end
  return table.concat(uname), table.concat(dom)
end

local function smb_session_decision(user, mech, hardened)
  if user == "" then
    if hardened then return false, 0xc0000224 end
    return true, 0, user, mech
  end
  if real_string.lower(user) == "guest" then
    if hardened then return false, 0xc000006d end
    return true, 1, user, mech
  end
  if mech == "ntlm" and hardened then
    return false, 0xc000006d
  end
  return true, 0, user, mech
end

local function smb_tree_decision(name, session, hardened)
  local guest = (session and session.action == 1)
  if name == "ipc$" then
    if session then return 0, 0x80, 0x00000001, name end
    return 0xc000006d
  end
  if name == "public" then
    if guest or (not hardened) then
      return 0, 0x01, 0x0000001f, name
    end
    return 0xc0000022
  end
  if name == "print$" then
    if guest and not hardened then
      return 0, 0x03, 0x00000007, name
    end
    return 0xc0000022
  end
  if name == "dfs" then
    if not hardened then
      return 0x0016, 0x01, 0x00000001, name
    end
    return 0xc00000cf
  end
  if name == "admin$" or real_string.match(name, "^%a$$") ~= nil then
    return 0xc0000022
  end
  return 0xc00000cf
end

local function smb_utf16le_to_ascii(p)
  local plain = {}
  for i = 1, #p, 2 do
    table.insert(plain, real_string.char(p:byte(i)))
  end
  return table.concat(plain)
end

"""
