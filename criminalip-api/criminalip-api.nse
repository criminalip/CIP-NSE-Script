local http = require "http"
local io = require "io"
local ipOps = require "ipOps"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local openssl = stdnse.silent_require "openssl"





-- Set your Criminal IP API key here to avoid typing it in every time:
local apiKey = ""

author = "Bo Gab <bkhwang@aispera.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

description = [[
Queries Criminal IP API for given targets and produces similar output to
a -sV nmap scan. The Criminal IP key can be set with the 'apikey' script
argument, or hardcoded in the .nse file itself. You can get a free key after register Criminal IP(https://criminalip.io).

]]

---
-- @usage
--  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP,criminalip-api.apikey=Your x-api-key'
--  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP' # when you set your api-key on script
--
-- @output
-- | criminalip-api: 
-- | Result for target IP (Hostname: hostname)
-- | Tag: hosting, vpn, mobile
-- | Category: MISP, Phishing
-- | AS_Name: as_name
-- | Country: US(City: Queens) 
-- | Score:
-- |  Inbound: Critical / Outbound: Critical
-- | Port  Socket  Scan Time            Product        Version  CVE
-- | 80    tcp     2022-11-27 21:54:51  xml            1.0      
-- | 111   tcp     2022-11-27 13:16:11                          
-- | 443   tcp     2022-11-20 12:56:45  HTML 5.0                
-- | 53    udp     2022-12-12 08:35:18  Dnsmasq        2.40     CVE-2021-3448, CVE-2020-25687, CVE-2020-25686, CVE-2020-25685, CVE-2020-25684
-- | 22    tcp     2022-11-29 19:10:11  Dropbear sshd           
-- |_111   udp     2022-11-28 09:26:14  rpcbind        2   


-- Begin
if not nmap.registry[SCRIPT_NAME] then
  nmap.registry[SCRIPT_NAME] = {
    apiKey = stdnse.get_script_args(SCRIPT_NAME .. ".apikey") or apiKey,
    count = 0
  }
end
local registry = nmap.registry[SCRIPT_NAME]
local outFile = stdnse.get_script_args(SCRIPT_NAME .. ".filename")
local arg_target = stdnse.get_script_args(SCRIPT_NAME .. ".target")

local function lookup_target (target)
  local response = http.get("api.criminalip.io",443,"/v1/ip/data?ip="..target.. '&full=ture', {header={['x-api-key']=registry.apiKey}})
  local stat, resp = json.parse(response.body)
  if not stat then
    stdnse.debug1("Error parsing Criminal IP response: %s", resp)
    return nil
  elseif resp.status ~= 200 then
    stdnse.debug1("Bad response from Criminal IP for IP %s : %s", target, resp.status)
    return nil
  end
  return resp
end

local function format_output(resp)
  local product_table = {}
  local version_table = {}
  local cve_table = {}
  local socket_table = {}
  local hostname_table = {}
  local test_table = {}
  local score_table = {}
  local tag_table = {}
  local tag_list = {}
  local category_table = {}
  local category_list = {}
  local confirmed_time_table = {}
  local score_to_str = {[1]='Safe',[2]='Low',[3]='Moderate',[4]='Dangerous',[5]='Critical'}
  local tag_str = {['is_vpn']='vpn',['is_cloud']='cloud',['is_proxy']='proxy',['is_tor']='tor',['is_hosting']='hosting',['is_mobile']='mobile',['is_scanner']='scanner',['is_snort']='snort'}
  
  for key, item in pairs(resp.whois.data) do
    as_name = item.as_name
    country = item.org_country_code:upper()
    if type(item.city) == "table" then
      city = ''
    else
      city = item.city
    end
  end

  for key, item in pairs(resp.tags) do
    if item == true then
      key = tag_str[key]
      table.insert(tag_table,key)
      tag_list['tag_key'] = tag_table
    end
  end

  if #tag_table == 0 then
    tag_list = ''
  else
    for key, item in pairs(tag_list) do
      tag_list = table.concat(item,", ")   
    end
  end


  for key, item in pairs(resp.score) do 
    if key == 'inbound' then
      score_table['inbound'] = score_to_str[item]
    else
      score_table['outbound'] = score_to_str[item]
    end
  end

  for key, item in pairs(resp.hostname.data) do
    hostname_table[1] = item.domain_name_full
  end
  
  if hostname_table[1] == nil then
    hostname_table[1] = ''
  end

  for key, item in pairs(resp.ip_category.data) do
    s = item.confirmed_time
    p = "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)"
    local year,month,day = s:match(p)
    local convert_time  = os.time({year=year,month=month,day=day})
    daysfrom = os.difftime(os.time(), convert_time) / (24 * 60 * 60)
    wholedays = math.floor(daysfrom)
    if wholedays <= 30 then
      if string.find(item.detect_source,'twitter') ~= nil then
        item.type = 'Twitter'
      end
      table.insert(category_table,item.type)
    end 
  end

  local hash = {}
  for key, value in ipairs(category_table) do
    if (not test_table[value]) then
      hash[#hash+1] = value
      test_table[value] = true 
    end
  end

  category_list['category_key'] = hash

  if #category_table == 0 then
    category_list = ''
  else
    for key, item in pairs(category_list) do
      category_list = table.concat(item,", ")   
    end
  end

  for key, item2 in pairs(resp.port.data) do
    s = item2.confirmed_time
    p = "(%d+)-(%d+)-(%d+) (%d+):(%d+):(%d+)"
    local year,month,day = s:match(p)
    local convert_time  = os.time({year=year,month=month,day=day})
    daysfrom = os.difftime(os.time(), convert_time) / (24 * 60 * 60)
    wholedays = math.floor(daysfrom)
    if wholedays <= 60 then
      table.sort(resp.port.data,function(a,b) return a.confirmed_time> b.confirmed_time end)
      if socket_table[item2.open_port_no] == nil  then
        if product_table[item2.open_port_no] == nil or product_table[item2.open_port_no] == "Unknown"  then
          product_table[item2.open_port_no] = item2.app_name
        end
        if version_table[item2.open_port_no] == nil or version_table[item2.open_port_no] == "Unknown" then
          version_table[item2.open_port_no] = item2.app_version
        end
        socket_table[item2.open_port_no] = item2.socket
        confirmed_time_table[item2.open_port_no] = item2.confirmed_time
      elseif socket_table[item2.open_port_no] ~= item2.socket then
        if product_table[item2.socket] == nil or product_table[item2.socket] == "Unknown"  then
          product_table[item2.socket] = item2.app_name
        end
        if version_table[item2.socket] == nil or version_table[item2.socket] == "Unknown" then
          version_table[item2.socket] = item2.app_version
        end
        socket_table[item2.socket] = item2.open_port_no
        confirmed_time_table[item2.socket] = item2.confirmed_time
      end
    end
  end

  for key, item in ipairs(resp.vulnerability.data) do
    for key, item3 in ipairs(item.open_port_no) do
      if cve_table[item3.port] == nil then
        cve_table[item3.port] = {}
      end
      table.insert(cve_table[item3.port], item.cve_id)
    end
  end
  
  for key,item in pairs(cve_table) do
    local item_count = #cve_table[key]
    if item_count > 5 then
      cve_table[key] = table.concat(item,", ",1,5)
    else
      cve_table[key] = table.concat(item,", ")
    end
  end
  
  local tab_out = tab.new()
  tab.addrow(tab_out, "Port","Socket", "Scan Time", "Product", "Version", "CVE")
  for i , v in pairs(product_table) do
    if cve_table[i] == nil then
      cve_table[i] = ''
    end
    if product_table[i] == 'Unknown' or product_table[i] == 'N/A' then
      product_table[i] = ''
    end
    if version_table[i] == 'Unknown' or version_table[i] == 'N/A' then
      version_table[i] = ''
    end
    if i ~= 'tcp' and i ~='udp' then 
      tab.addrow(tab_out,i,socket_table[i],confirmed_time_table[i],product_table[i],version_table[i],cve_table[i])
    else
      if cve_table[socket_table[i]] == nil then
        cve_table[socket_table[i]] = ''
      end
      tab.addrow(tab_out,socket_table[i],i,confirmed_time_table[i],product_table[i],version_table[i],cve_table[socket_table[i]])
    end
  end
  registry.count = registry.count + 1
  return city, as_name, country, hostname_table, score_table, tag_list, category_list, tab.dump(tab_out)

end

prerule = function ()
  if (outFile ~= nil) then
    local csv_file = io.open(outFile, "w")
    io.output(csv_file)
    io.write("IP,Hostname,AS_Name,Country,City,Score(Inbound),Score(Outbound)\n")
  else
    csv_file = io.stdout
  end

  if registry.apiKey == "" then
    registry.apiKey = nil
  end

  if not registry.apiKey then
    stdnse.verbose1("Error: Please specify your Criminal IP key with the %s.apikey argument", SCRIPT_NAME)
    return false
  end


  local response = http.post("api.criminalip.io", 443, "/v1/user/me", {header={['x-api-key']=registry.apiKey}})
  local stat, resp = json.parse(response.body)
  if (resp.status == 401) then
    stdnse.verbose1("Error: Your CriminalIP API key (%s) is invalid", registry.apiKey)
    return false
  elseif (resp.status == 414 or resp.status == 415) then
    stdnse.verbose1("Error: You are not Criminal IP User. Please, Register First")
    return false
  elseif (resp.status ~= 200) then
    stdnse.verbose1("Error: Unexpected error occured")  
    -- Prevent further stages from running
    registry.apiKey = nil
    return false
  end

  if arg_target then
    local is_ip, err = ipOps.expand_ip(arg_target)
    if not is_ip then
      stdnse.verbose1("Error: %s.target must be an IP address", SCRIPT_NAME)
      return false
    end
    return true
  end
end


generic_action = function(ip)
  local resp = lookup_target(ip)
  if not resp then return nil end
  local city, as_name, country, hostname_table,score_table,tag,category,tabular = format_output(resp)
  local hostname = hostname_table[1]
  local inbound_score = score_table['inbound']
  local outbound_score = score_table['outbound']
  local result = string.format(
    "\nResult for %s (Hostname: %s)\nTag: %s\nCategory: %s\nAs_Name: %s\nCountry: %s(City: %s)\nScore\n Inbound: %s / Outbound: %s\n%s",
    ip,
    hostname,
    tag,
    category,
    as_name,
    country,
    city,
    inbound_score,
    outbound_score,
    tabular
    )
    if (outFile ~= nil) then
      io.write( string.format("%s,%s,%s,%s,%s,%s,%s\n",
          ip, hostname,as_name,country,city,inbound_score,outbound_score)
        )
    end
  return  result
end

preaction = function()
  return generic_action(arg_target)
end

hostrule = function(host)
  return registry.apiKey and not ipOps.isPrivate(host.ip)
end

postrule = function ()
  return registry.apiKey
end

postaction = function ()
  local out = { "Criminal IP Search done: ", registry.count, " hosts up." }
  if outFile then
    io.close()
    -- out[#out+1] = outFile
  end
  return table.concat(out)
end

local ActionsTable = {
  -- prerule: scan target from script-args
  prerule = preaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
