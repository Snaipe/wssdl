--
--  Copyright 2016 diacritic <https://diacritic.io>
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.

local wssdl = {}

wssdl.field_type = function (t, basesz)
  return function (s)
    return { size = function () return s * basesz end, type = t }
  end
end

wssdl.bits  = wssdl.field_type ("bits", 1)
wssdl.bytes = wssdl.field_type ("bytes", 8)
wssdl.sint  = wssdl.field_type ("signed", 1)
wssdl.uint  = wssdl.field_type ("unsigned", 1)
wssdl.float = wssdl.field_type ("float", 8)

wssdl.bit  = wssdl.bits(1)

wssdl.i8  = wssdl.sint(8)
wssdl.i16 = wssdl.sint(16)
wssdl.i32 = wssdl.sint(32)
wssdl.i64 = wssdl.sint(64)

wssdl.u8  = wssdl.uint(8)
wssdl.u16 = wssdl.uint(16)
wssdl.u32 = wssdl.uint(32)
wssdl.u64 = wssdl.uint(64)

wssdl.f32 = wssdl.float(4)
wssdl.f64 = wssdl.float(8)

print(wssdl.bytes(4).size())

wssdl.packet = {

  __create = function (pkt, params)
    local obj = {}
    obj.fields = params

    obj.size = function (pkt)
        local sz = 0
        if type(pkt.size) == 'function' then
          for k, v in pairs(pkt.fields) do
            sz = sz + v:size()
          end
        else
          sz = tonumber(pkt.size)
        end
        if pkt.padding ~= nil and pkt.padding > 0 then
          -- no bitwise ops, we align up the old way
          local rem = sz % pkt.padding
          if rem > 0 then
            sz = sz - rem + pkt.padding
          end
        end
        return sz
      end

    return obj
  end;

  _padded = function (pkt, pad)
    pkt.padding = pad
  end;

}

setmetatable(wssdl.packet, {

  __index = function(t, k)
    print('k:', k)
    if k:sub(1,1) == '_' then
      return nil
    end

    local field = t['_' .. k]

    if field ~= nil then
      return function (_, ...)
        local clone = {}
        for k, v in pairs(t) do clone[k] = v end
        setmetatable(clone, getmetatable(t))

        field(clone, ...)
        return clone
      end
    end
  end;

  __call = function(t, ...)
    return t.__create(t, ...)
  end;

})

return wssdl
