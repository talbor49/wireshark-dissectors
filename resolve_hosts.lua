-- Wireshark post-dissector to help resolve IPs to host-names

-- Existing IP fields to use as input
local ip_src_field = Field.new("ip.src")
local ip_dst_field = Field.new("ip.dst")


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

		-- Set the value of our fields
		subtree:add(resolved_src, tostring(src_host))
		subtree:add(resolved_dst, tostring(dst_host))
	end
end


-- Register the post dissector 
register_postdissector(myproto)