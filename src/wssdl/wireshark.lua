--
--  Copyright 2016 diacritic <https://diacritic.io>
--
--  This file is part of wssdl <https://github.com/diacritic/wssdl>.
--
--  wssdl is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  wssdl is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with wssdl.  If not, see <http://www.gnu.org/licenses/>.

local ws = {}

local utils = require 'wssdl.utils'

ws.make_fields = function (fields, pkt, prefix)
  local prefix = prefix or ''

  for i, field in ipairs(pkt._definition) do
    local ftype = nil
    if field._type == 'packet' then
      -- No need to deepcopy the packet definition since the parent was cloned
      local pkt = field._packet
      pkt._properties.noclone = true
      ws.make_fields(fields, pkt, prefix .. field._name .. '.')
      ftype = ftypes.STRING
    elseif field._type == 'payload' then
      ftype = ftypes.PROTOCOL
    elseif field._type == 'string' then
      local tname = 'STRING'
      if type(field._size) == 'number' and field._size == 0 then
        tname = tname .. 'Z'
      end
      ftype = ftypes[tname]
    elseif field._type == 'address' then
      if field._size == 32 then
        ftype = ftypes.IPv4
      else
        -- Older versions of wireshark does not support ipv6 protofields in
        -- their lua API. See https://code.wireshark.org/review/#/c/18442/
        -- for a follow up on the patch to address this
        if utils.semver(get_version()) >= utils.semver('2.3.0') then
          ftype = ftypes.IPv6
        else
          ftype = ftypes.STRING
        end
      end
    elseif field._type == 'bits' then
      local len = #field
      if type(len) == 'number' then
        local tname = 'UINT' .. tostring(math.ceil(len / 8) * 8)
        ftype = ftypes[tname]
      else
        ftype = ftypes.UINT64
      end
    elseif field._type == 'float' then
      local len = #field
      if type(len) ~= 'number' then
        error('wssdl: Cannot compute size of primitive ' .. utils.quote(field._name) .. ' field.')
      end
      if len == 4 then
        ftype = ftypes.FLOAT
      else
        ftype = ftypes.DOUBLE
      end
    else
      local corr = {
        signed   = 'INT',
        unsigned = 'UINT',
        bytes    = 'BYTES',
        bool     = 'BOOLEAN',
      }

      local tname = corr[field._type]
      if field._type == 'signed' or field._type == 'unsigned' then
        local len = #field
        if type(len) ~= 'number' then
          error('wssdl: Cannot compute size of primitive ' .. utils.quote(field._name) .. ' field.')
        end
        tname = tname .. tostring(len)
      end

      ftype = ftypes[tname]
    end

    local format = nil
    if field._format ~= nil then
      local corr = {
        decimal = base.DEC,
        hexadecimal = base.HEX,
        octal = base.OCT,
      }
      format = corr[field._format]
    end

    fields[prefix .. field._name] = ProtoField.new(
        field._displayname or field._name,
        prefix .. field._name,
        ftype,
        nil,
        format,
        nil,
        field._description)
  end
end

ws.dissector = function (pkt, proto)
  local dissect_pkt = nil

  dissect_pkt = function(pkt, prefix, start, buf, pinfo, tree, root)
    local prefix = prefix or ''
    local idx = start
    local pktval = {}

    for i, field in ipairs(pkt._definition) do

      local protofield = proto.fields[prefix .. field._name]
      local node = nil
      local sz = nil
      local val = nil

      if field._type == 'packet' then
        local rawval = buf(math.floor(idx / 8))
        node = tree:add(protofield, rawval, '')
        sz, val = dissect_pkt(field._packet, prefix .. field._name .. '.', idx % 8, rawval:tvb(), pinfo, node, root)
        -- Handle errors
        if sz < 0 then
          return sz
        end
      end
      sz = #field

      if sz and type(sz) ~= 'number' then
        pkt:eval(pktval)
        sz = #field
      end

      if sz and type(sz) ~= 'number' then
        error('wssdl: Cannot evaluate size of ' .. utils.quote(field._name) .. ' field.')
      end

      if sz == nil then
        sz = buf:len() * 8 - idx
      end

      local offlen = math.ceil((sz + idx % 8) / 8)
      local needed = math.floor(idx / 8) + offlen

      local rawval = buf(0,0)
      if sz > 0 then
        if needed > buf:len() then
          tree:add_proto_expert_info(proto.experts.too_short)
          return -1
        end
      end

      if needed <= buf:len() and sz > 0 then
        rawval = buf(math.floor(idx / 8), offlen)
      end

      if field._type == 'packet' then
        node:set_len(offlen)
      elseif field._type == 'payload' then
        local dtname = field._dt_name or
            table.concat({string.lower(proto.name),
                          unpack(field._dissection_criterion)}, '.')

        local dt = DissectorTable.get(dtname)
        local val = pktval
        for i, v in pairs(field._dissection_criterion) do
          val = val[v]
        end
        dt:try(val, rawval:tvb(), pinfo, root)
      elseif field._type == 'string' then
        local mname = 'string'
        if type(field._size) == 'number' and field._size == 0 then
          rawval = buf(math.floor(idx / 8))
          mname = mname .. 'z'
        end
        if field._basesz == 2 then
          mname = 'u' .. mname
        end
        val = rawval[mname](rawval)
        sz = #val
      elseif field._type == 'address' then
        local mname = field._size == 32 and 'ipv4' or 'ipv6'

        -- Older versions of wireshark does not support ipv6 protofields in
        -- their lua API. See https://code.wireshark.org/review/#/c/18442/
        -- for a follow up on the patch to address this
        if utils.semver(get_version()) < utils.semver('2.3.0') and mname == 'ipv6' then
          val = rawval:bytes()
          local ip = ''
          for i=0,7 do
            local n = rawval(i*2,2):uint()
            if n ~= 0 then
              if i > 0 and ip == '' then
                ip = ':'
              end
              ip = ip .. string.format('%x', n)
              if i < 7 then
                ip = ip .. ':'
              end
            elseif i == 7 then
              ip = ip .. ':'
            end
          end
          node = tree:add(protofield, rawval, ip, (field._displayname or field._name) .. ': ', ip)
        else
          val = rawval[mname](rawval)
        end
      elseif field._type == 'bits' or field._type == 'bool' then
        if sz > 64 then
          error('wssdl: "' .. field._type .. '" field ' .. field._name .. ' is larger than 64 bits, which is not supported by wireshark.')
        end
        val = rawval:bitfield(idx % 8, sz)
      elseif field._type == 'bytes' then
        if idx % 8 > 0 then
          error ('Unaligned "bytes" fields are not supported')
        end
        val = tostring(rawval:bytes())
      else
        if idx % 8 > 0 then
          if sz > 64 then
            error('wssdl: Unaligned "' .. field._type .. '" field ' .. field._name .. ' is larger than 64 bits, which is not supported by wireshark.')
          end
          local corr = {
            signed   = '>i',
            unsigned = '>I',
            float    = '>f',
          }
          local packed = Struct.pack('>I' .. tostring(math.ceil(sz / 8)), rawval:bitfield(idx % 8, sz))
          local fmt = corr[field._type]
          if field._type ~= 'float' then
            fmt = fmt .. tostring(math.ceil(sz / 8))
          end

          val = Struct.unpack(fmt, packed)
        else
          local corr = {
            signed   = 'int',
            unsigned = 'uint',
            float    = 'float',
          }
          val = rawval[corr[field._type]](rawval)
        end
      end

      if node == nil then
        tree:add(protofield, rawval, val)
      end
      pktval[field._name] = val

      idx = idx + sz
    end

    return idx, pktval
  end

  return function(buf, pinfo, tree)
    local pkt = utils.deepcopy(pkt)

    -- Don't clone the packet definition further when evaluating
    pkt._properties.noclone = true

    pinfo.cols.protocol = proto.name
    local subtree = tree:add(proto, buf(), proto.description)

    local len, _ = dissect_pkt(pkt, string.lower(proto.name) .. '.', 0, buf, pinfo, subtree, tree)
    if len < 0 then
      return
    end
    return math.ceil(len / 8)
  end
end

ws.proto = function (pkt, name, description)
  local proto = Proto.new(name, description)
  ws.make_fields(proto.fields, pkt, string.lower(name) .. '.')

  proto.experts.too_short = ProtoExpert.new(
  string.lower(name) .. '.too_short.expert',
  name .. ' message too short',
  expert.group.MALFORMED, expert.severity.ERROR)

  proto.dissector = ws.dissector(pkt, proto)
  return proto
end

return ws
