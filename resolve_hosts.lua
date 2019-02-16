-- Wireshark post-dissector to help resolve IPs to host-names by file
-- Reads the hosts file located in the path specified below.
-- His format should be lines, starting with an IPv4 address, a space, and the hostname.
---- For example:
------ 192.168.1.1 Net router
------ 192.168.1.21 My Computer
-- Place the file in Wireshark directory (probably C:\Program Files\Wireshark\hosts.txt)
local hosts_file = 'hosts.txt'
-- Host resolving be also done by placing a hosts file in %APPDATA%\wireshark\hosts , but this method does not allow spaces in hostname.

-- Regular expression to verify that line starts with and IP address, and then a space
ip_regex = "^(%d+)%.(%d+)%.(%d+)%.(%d+) "


-- Existing IP fields to use as input
local ip_src_field = Field.new("ip.src")
local ip_dst_field = Field.new("ip.dst")


-- Check if the file exists
function file_exists(file)
  local f = io.open(file, "rb")
  if f then f:close() end
  return f ~= nil
end


-- Get all lines from a file, returns an empty 
-- list/table if the file does not exist
-- Ignore lines that are not according to the format specified in the beginnning of the file.
function read_host_lines(file)
  if not file_exists(file) then return {} end
  lines = {}
  for line in io.lines(file) do 
  	if string.find(line, ip_regex) then
	    lines[#lines + 1] = line
	end
  end
  return lines
end

-- Split a line, to the string until the first space, and after the first space.
-- In our case will return the ip and his corresponding hostname
function split_ip_and_host(line)
        i, j = string.find(line, " ")
        local ip = string.sub(line, 1, j-1)
        local host = string.sub(line, j+1)
        return ip, host
end

-- Read lines from hosts file
local lines = read_host_lines(hosts_file)

-- Maps between IP and hostname
hosts = {}

for k,v in pairs(lines) do
  ip, host = split_ip_and_host(v)
  hosts[ip] = host
end	



-- Define our protocol
local myproto = Proto("resolve_host", "Resolve hosts")
-- Fields of protocol
local resolved_src = ProtoField.string("resolve_host.resolved_src", "Resolved Source")
local resolved_dst = ProtoField.string("resolve_host.resolved_dst", "Resolved Destination")
myproto.fields = {
	resolved_src,
	resolved_dst
}

-- This function will run for every packet
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

		-- If src host is resolved, set the resolved src field
		if hosts[src_host_str] then
			subtree:add(resolved_src, hosts[src_host_str])
		end

		-- If dst host is resolved, set the resolved dst field
		if hosts[dst_host_str] then
			subtree:add(resolved_dst, hosts[dst_host_str])
		end
	end
end


-- Register our post dissector 
register_postdissector(myproto)