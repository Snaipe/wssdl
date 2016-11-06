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

local wssdl = {}

require('wssdl.bit') -- Monkey-patch 'bit' library

local placeholder = require 'wssdl.placeholder' :init(wssdl)
local utils       = require 'wssdl.utils'
local ws          = require 'wssdl.wireshark'
local debug       = require 'wssdl.debug'

local initenv = function ()
  -- The user environment is 4 stack levels up
  wssdl.env, wssdl.fenv = debug.getfenv(4)
end

local make_fields = nil

wssdl._packet = {

  _properties = {
    padding = 0,          -- Padding, in bytes.
    size = 0,             -- Static size, in bytes.
    desegment = false,    -- Whether the packet should be desegmented or not
  };

  _create = function(pkt, def)
    local newpacket = {}

    newpacket = {
      _definition = def,
      _values = {},
      _properties = pkt._properties,

      _imbue = function (field, ...)
        local pkt = newpacket:eval({...})
        field._type    = "packet"
        field._packet  = pkt
        return field
      end;

      eval = function (pkt, params)
        if next(params) == nil then
          return pkt
        end

        if not pkt._properties.noclone then
          pkt = utils.deepcopy(pkt)
        end

        for i, v in ipairs(pkt._definition) do
          local def = v:_eval(params)
          if def == nil then
            table.remove(pkt._definition, i)
          else
            pkt._definition[i] = def
          end
        end

        -- Recompute lookup
        pkt._lookup = {}
        for i, v in ipairs(pkt._definition) do
          pkt._lookup[v._name] = i
        end

        return pkt
      end;

      proto = ws.proto

    }

    newpacket._lookup = {}
    for i, v in ipairs(def) do
      newpacket._lookup[v._name] = i
    end

    newpacket.fields = {}
    setmetatable(newpacket.fields, {

      __index = function(_, k)
        local idx = newpacket._lookup[k]
        if idx ~= nil then
          return newpacket._definition[idx]
        end
      end

    })

    setmetatable(newpacket, {
      __len = pkt._calcsize;
    })

    return newpacket
  end;

  padding = function(pkt, pad)
    pkt._properties.padding = pad
    return pkt
  end;

  size = function(pkt, sz)
    pkt._properties.size = sz
    return pkt
  end;

  desegment = function(pkt, dseg)
    pkt._properties.desegment = dseg or true
    return pkt
  end;

  _calcsize = function(pkt)
    local sz = 0
    if pkt._properties.size > 0 then
      sz = tonumber(pkt.size)
    else
      for _, v in ipairs(pkt._definition) do
        sz = sz + #v
      end
    end
    if pkt._properties.padding > 0 then
      local mask = pkt._properties.padding - 1
      sz = bit.band(sz + mask, bit.bnot(mask))
    end
    return sz
  end;

}

wssdl._current_def = nil

setmetatable(wssdl._packet, {

  __call = function(pkt, ...)
    -- Restore the original global metatable
    debug.setfenv(wssdl.fenv, wssdl.env)
    -- The user environment is 3 stack levels up
    debug.set_locals(3, wssdl._locals)

    local out = pkt._create(pkt, ...)

    for k, v in pairs(wssdl._current_def) do
      if k:sub(1,1) ~= '_' then
        v._pktdef = nil
      end
    end
    wssdl._current_def = nil
    return out
  end;

})

local packetdef_metatable = nil

local make_packetdef_placeholder

make_packetdef_placeholder = function(t, k)

  local o = {
    _name = k;
    _pktdef = wssdl._current_def;

    -- Evaluate the field with concrete values
    _eval = function(field, params)
      for k, v in pairs(field) do
        field[k] = placeholder.do_eval(v, params)
      end
      return field
    end
  }
  setmetatable(o, placeholder.metatable(_G, packetdef_metatable, make_packetdef_placeholder))
  return o
end;

packetdef_metatable = {

  __index = function(t, k)
    local o = make_packetdef_placeholder(t, k)

    -- Restore the original global metatable
    debug.setfenv(wssdl.fenv, wssdl.env)
    -- The user environment is 3 stack levels up
    debug.set_locals(3, wssdl._locals)

    return o
  end;

}

local dissectdef_metatable = nil

local make_dissectdef_placeholder

make_dissectdef_placeholder = function(ctx, k)
  local o = {
    _path = { k };
  }

  setmetatable(o, {

    __index = function(t, k)
      -- Restore the original global metatable
      debug.setfenv(wssdl.fenv, wssdl.env)
      -- The user environment is 3 stack levels up
      debug.set_locals(3, wssdl._locals)

      t._path[#t._path + 1] = k
      return t
    end;

    __call = function(t, _, params)
      local method = t._path[#t._path]
      t._path[#t._path] = nil
      local tname = table.concat(t._path, '.')
      local ok, dt = pcall(DissectorTable.get, tname)
      if not ok then
        error('wssdl: DissectorTable ' .. utils.quote(tname) .. ' does not exist.', 2)
      end
      for k, v in pairs(params) do
        dt[method](dt, k, v)
      end
      -- Switch to the dissect definition metatable
      local env = setmetatable({}, dissectdef_metatable())
      debug.setfenv(wssdl.fenv, env)
      -- The user environment is 3 stack levels up
      wssdl._locals = debug.get_locals(3)
      debug.reset_locals(3, nil, make_dissectdef_placeholder)
    end;

  })
  return o
end

dissectdef_metatable = function(newdissect)
  return {

    __index = function(t, k)
      local o = make_dissectdef_placeholder(t, k)

      -- Restore the original global metatable
      debug.setfenv(wssdl.fenv, wssdl.env)
      -- The user environment is 3 stack levels up
      debug.set_locals(3, wssdl._locals)

      return o
    end;

  }
end

setmetatable(wssdl, {

  __index = function(t, k)
    initenv()
    if k == 'packet' then
      -- Create a new packet factory based off wssdl._packet
      local newpacket = {}
      for k, v in pairs(wssdl._packet) do newpacket[k] = v end

      local newprops = {}
      for k, v in pairs(wssdl._packet._properties) do newprops[k] = v end
      newpacket._properties = newprops
      setmetatable(newpacket, getmetatable(wssdl._packet))

      wssdl._current_def = { _pktdef = newpacket }

      -- Switch to the packet definition metatable
      local env = setmetatable({}, packetdef_metatable)
      debug.setfenv(wssdl.fenv, env)
      -- The user environment is 3 stack levels up
      wssdl._locals = debug.get_locals(3)
      debug.reset_locals(3, nil, make_packetdef_placeholder)
      return newpacket
    elseif k == 'dissect' then
      local newdissect = {}

      setmetatable(newdissect, {

        __call = function(dissect, ...)
          -- Restore the original global metatable
          debug.setfenv(wssdl.fenv, wssdl.env)
          debug.set_locals(3, wssdl._locals)
          return nil
        end;

      })

      -- Switch to the dissect definition metatable
      local env = setmetatable({}, dissectdef_metatable(newdissect))
      debug.setfenv(wssdl.fenv, env)

      -- The user environment is 3 stack levels up
      wssdl._locals = debug.get_locals(3)
      debug.reset_locals(3, nil, make_dissectdef_placeholder)

      return newdissect
    end
  end;

})

wssdl.dissector = ws.dissector

return wssdl
