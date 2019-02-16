-- Wireshark post-dissector to help resolve IPs to host-names

-- Existing IP fields to use as input
local ip_src_field = Field.new("ip.src")
local ip_dst_field = Field.new("ip.dst")

-- see if the file exists
function file_exists(file)
  local f = io.open(file, "rb")
  if f then f:close() end
  return f ~= nil
end

ip_regex = "^(%d+)%.(%d+)%.(%d+)%.(%d+) "

-- get all lines from a file, returns an empty 
-- list/table if the file does not exist
function lines_from(file)
  if not file_exists(file) then return {} end
  lines = {}
  for line in io.lines(file) do 
  	if string.find(line, ip_regex) then
	    lines[#lines + 1] = line
	end
  end
  return lines
end

function ip_to_host(line)
        i, j = string.find(line, " ")
        local ip = string.sub(line, 1, j-1)
        local host = string.sub(line, j+1)
        return ip, host
end

-- tests the functions above
local file = 'C:\\Users\\tal\\Desktop\\hosts.txt'
local lines = lines_from(file)

hosts = {}

for k,v in pairs(lines) do
  -- print('line[' .. k .. ']', v)
  ip, host = ip_to_host(v)
  hosts[ip] = host
end	




local myproto = Proto("resolve_host", "Resolve hosts")
-- Fields of protocol
local resolved_src = ProtoField.string("resolve_host.resolved_src", "Resolved Source")
local resolved_dst = ProtoField.string("resolve_host.resolved_dst", "Resolved Destination")
myproto.fields = {
	resolved_src,
	resolved_dst
}

-- This function will be ran for every packet
function myproto.dissector(tvb, pinfo, tree)
	-- tvb: The buffer to dissect.
	-- pinfo - The packet info.
	-- tree - The tree on which to add the protocol items.
	local src_host = ip_src_field()
	local dst_host = ip_dst_field()
	-- Only dissect if it's an IP packet
	if src_host and dst_host then
		-- Add our fake protocol to the tree
		local subtree = tree:add(myproto)
		-- Don't show our fields - they are only made to be used as a column
		subtree:set_hidden(true)
		-- Convert fields to string
		local src_host_str = tostring(src_host)
		local dst_host_str = tostring(dst_host)

		if hosts[src_host_str] then
			subtree:add(resolved_src, hosts[src_host_str])
		end

		if hosts[dst_host_str] then
			subtree:add(resolved_dst, hosts[dst_host_str])
		end
		-- Set the value of our fields

		-- print("Printing lines!")
		-- for k,v in pairs(hosts) do
		-- 	print('hosts[' .. k .. ']', v)
		-- end
		-- -- print all line numbers and their contents
		-- os.execute("CHOICE /n /d:y /c:yn /t:5")
	end
end


-- Register the post dissector 
register_postdissector(myproto)