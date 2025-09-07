-- DART protocol plugin for Wireshark
-- author: rancho.dart@qq.com

-- Copy this file to <Wireshark_installation_dir>/plugins/

local dart_proto = Proto("DART", "Domain Aware Routing Protocol")

-- fields definition
local f = dart_proto.fields
f.version = ProtoField.uint8("dart.version", "Version", base.DEC)
f.proto   = ProtoField.uint8("dart.proto", "Protocol", base.DEC)
f.dst_len = ProtoField.uint8("dart.dst_len", "Destination FQDN Length", base.DEC)
f.dst     = ProtoField.string("dart.dst", "Destination FQDN")
f.src_len = ProtoField.uint8("dart.src_len", "Source FQDN Length", base.DEC)
f.src     = ProtoField.string("dart.src", "Source FQDN")

-- protocol mapping
local dissectors = {
    [1] = Dissector.get("icmp"),
    [6] = Dissector.get("tcp"),
    [17] = Dissector.get("udp")
}
local PROTOCOL_MAP = {
    [1] = "ICMP",
    [6] = "TCP",
    [17] = "UDP"
}

function dart_proto.dissector(buffer, pinfo, tree)
    local offset = 0
    pinfo.cols.protocol = "DART"
    local darttree = tree:add(dart_proto, buffer(), "DART Protocol Experimental (UDP Port 0xDA27)")

    -- Version
    darttree:add(f.version, buffer(offset, 1))
    local version = buffer(offset, 1):uint()
    offset = offset + 1
    if version ~= 1 then
        darttree:add_expert_info(PI_MALFORMED, PI_ERROR, "Unsupported DART version")
        return
    end

    -- Protocol
    local proto = buffer(offset, 1):uint()
    local proto_name = PROTOCOL_MAP[proto] or "UNKNOWN"
    darttree:add(f.proto, buffer(offset, 1)):append_text(" (" .. proto_name .. ")")
    offset = offset + 1

    -- Destination FQDN
    darttree:add(f.dst_len, buffer(offset, 1))
    local dst_len = buffer(offset, 1):uint()
    offset = offset + 1

    darttree:add(f.src_len, buffer(offset, 1))
    local src_len = buffer(offset, 1):uint()
    offset = offset + 1

    if dst_len > 0 then
        darttree:add(f.dst, buffer(offset, dst_len))
        pinfo.cols.dst = buffer(offset, dst_len):string()
        offset = offset + dst_len
    end

    if src_len > 0 then
        darttree:add(f.src, buffer(offset, src_len))
        pinfo.cols.src = buffer(offset, src_len):string()
        offset = offset + src_len
    end

    local payload = buffer(offset)
    if payload:len() > 0 then
        local dissector = dissectors[proto]
        if dissector then
            pinfo.cols.protocol = "DART/" .. (PROTOCOL_MAP[proto] or "UNKNOWN")
            dissector:call(payload:tvb(), pinfo, tree)
        end
    end
end

-- register the dissector
local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(0xDA27, dart_proto)