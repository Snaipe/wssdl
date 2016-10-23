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

local deepcopy = function() end

deepcopy = function (o)
  if type(o) == 'table' then
    local copy = {}
    for k, v in pairs(o) do
      copy[k] = deepcopy(v)
    end
    setmetatable(copy, getmetatable(o))
    return copy
  else
    return o
  end
end

local quote = function(s)
  return '‘' .. s .. '’'
end

wssdl.init = function (self, env)
  self.env = env
  return self
end

wssdl.field_type = function (type, basesz)
  local o = {
    _imbue = function (field, s)
      field._size = s * basesz
      field._type = type
      return field
    end
  }
  return o
end

wssdl.field_type_sized = function (type, size)
  local o = {
    _imbue = function (field)
      field._size = size
      field._type = type
      return field
    end
  }
  return o
end

local format_specifier = function(fmt)
  local o = {
    _imbue = function(field)
      field._format = fmt
      return field
    end
  }
  return o
end

wssdl.field_types = {
  bits  = wssdl.field_type("bits",      1);
  bytes = wssdl.field_type("bytes",     8);
  int   = wssdl.field_type("signed",    1);
  uint  = wssdl.field_type("unsigned",  1);

  bit = wssdl.field_type_sized("bits", 1);

  i8  = wssdl.field_type_sized("signed", 8);
  i16 = wssdl.field_type_sized("signed", 16);
  i32 = wssdl.field_type_sized("signed", 32);
  i64 = wssdl.field_type_sized("signed", 64);

  u8  = wssdl.field_type_sized("unsigned", 8);
  u16 = wssdl.field_type_sized("unsigned", 16);
  u32 = wssdl.field_type_sized("unsigned", 32);
  u64 = wssdl.field_type_sized("unsigned", 64);

  f32 = wssdl.field_type_sized("float", 32);
  f64 = wssdl.field_type_sized("float", 64);

  bool = {
    _imbue = function (field, s)
      field._size = (s or 1)
      field._type = "bool"
      return field
    end
  };

  payload = {
    _imbue = function(field, cr_expr, size)
      local criterion = {}
      if type(cr_expr) == 'string' then
        -- Split the dot-separated expression into a table
        local sep, fields = '\\.', {}
        local pattern = string.format("([^%s]+)", sep)
        cr_expr:gsub(pattern, function(c) fields[#fields+1] = c end)
        criterion = fields
      else
        local dt_name = nil
        -- We assume that if the _id member exists, we are dealing with
        -- a field placeholder. Otherwise, this is a property table
        if cr_expr._id == nil then
          dt_name = cr_expr[2] or cr_expr.name
          cr_expr = cr_expr[1] or cr_expr.criterion
        end

        while cr_expr do
          table.insert(criterion, 1, cr_expr._id)
          cr_expr = cr_expr._parent
        end
        field._dt_name = dt_name
      end
      field._dissection_criterion = criterion
      field._size = size
      field._type = "payload"
      return field
    end
  };

  oct = format_specifier('octal');
  dec = format_specifier('decimal');
  hex = format_specifier('hexadecimal');

  description = {
    _imbue = function(field, desc)
      field._description = desc
      return field
    end
  };

  name = {
    _imbue = function(field, str)
      field._displayname = str
      return field
    end
  };
}

local make_fields = nil

wssdl._packet = {

  _properties = {
    padding = 0,  -- Padding, in bytes.
    size = 0,     -- Static size, in bytes.
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
          pkt = deepcopy(pkt)
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

      protocol = function (pkt, name, description)
        local proto = Proto.new(name, description)
        make_fields(proto.fields, pkt, string.lower(name) .. '.')

        proto.experts.too_short = ProtoExpert.new(
            string.lower(name) .. '.too_short.expert',
            name .. ' message too short',
            expert.group.MALFORMED, expert.severity.ERROR)

        proto.dissector = wssdl.dissector(pkt, proto)
        return proto
      end

    }

    newpacket._lookup = {}
    for i, v in ipairs(def) do
      newpacket._lookup[v.name] = i
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

setmetatable(wssdl._packet, {

  __call = function(pkt, ...)
    -- Restore the original global metatable
    setmetatable(_G, nil)
    return pkt._create(pkt, ...)
  end;

})

local placeholder_metatable = {}

local do_eval = function (v, values)
  if type(v) == 'table' and v._eval ~= nil then
    return v:_eval(values)
  else
    return v
  end
end

local new_placeholder = function (eval)
  local obj = { _eval = eval }
  setmetatable(obj, placeholder_metatable)
  return obj
end

local new_binop_placeholder = function(eval)
  return function(lhs, rhs)
    local ph = new_placeholder(eval)
    ph._rhs = rhs
    ph._lhs = lhs
    return ph
  end
end

local new_valued_placeholder = function(eval)
  return function(value)
    local ph = new_placeholder(eval)
    ph._value = value
    return ph
  end
end

local new_funcall_placeholder = function(func, ...)
  local ph = new_placeholder (function(self, values)
      return self._func(unpack(self._params))
    end)
  ph._func = func
  ph._params = {...}
  return ph
end

local new_field_placeholder = function(id)
  local ph = new_placeholder (function(self, values)
      local val = values[self._id]
      if val ~= nil then
        return val
      else
        return new_field_placeholder(self._id)
      end
    end)
  ph._id = id
  return ph
end

local new_subscript_placeholder = function(parent, subscript)
  local ph = new_placeholder (function(self, values)
      return do_eval(self._parent, values)[self._id]
    end)
  ph._parent = parent
  ph._id = subscript
  return ph
end

local new_unm_placeholder = new_valued_placeholder (function(self, values)
    return -do_eval(self._value, values)
  end)

local new_add_placeholder = new_binop_placeholder (function(self, values)
    return do_eval(self._lhs, values) + do_eval(self._rhs, values)
  end)

local new_sub_placeholder = new_binop_placeholder (function(self, values)
    return do_eval(self._lhs, values) - do_eval(self._rhs, values)
  end)

local new_mul_placeholder = new_binop_placeholder (function(self, values)
    return do_eval(self._lhs, values) * do_eval(self._rhs, values)
  end)

local new_div_placeholder = new_binop_placeholder (function(self, values)
    return do_eval(self._lhs, values) / do_eval(self._rhs, values)
  end)

local new_pow_placeholder = new_binop_placeholder (function(self, values)
    return do_eval(self._lhs, values) ^ do_eval(self._rhs, values)
  end)

local new_mod_placeholder = new_binop_placeholder (function(self, values)
    return do_eval(self._lhs, values) % do_eval(self._rhs, values)
  end)

-- Bitwise ops

local new_band_placeholder = new_binop_placeholder (function(self, values)
    return bit.band(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_bor_placeholder = new_binop_placeholder (function(self, values)
    return bit.bor(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_bxor_placeholder = new_binop_placeholder (function(self, values)
    return bit.bxor(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_bnot_placeholder = new_valued_placeholder (function(self, values)
    return bit.bnot(do_eval(self._value, values))
  end)

local new_lshift_placeholder = new_binop_placeholder (function(self, values)
    return bit.lshift(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_rshift_placeholder = new_binop_placeholder (function(self, values)
    return bit.rshift(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_arshift_placeholder = new_binop_placeholder (function(self, values)
    return bit.arshift(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_rol_placeholder = new_binop_placeholder (function(self, values)
    return bit.rol(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_ror_placeholder = new_binop_placeholder (function(self, values)
    return bit.ror(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

local new_bswap_placeholder = new_valued_placeholder (function(self, values)
    return bit.bswap(do_eval(self._value, values))
  end)

local new_tobit_placeholder = new_valued_placeholder (function(self, values)
    return bit.tobit(do_eval(self._value, values))
  end)

local new_tohex_placeholder = new_binop_placeholder (function(self, values)
    return bit.tohex(do_eval(self._lhs, values), do_eval(self._rhs, values))
  end)

placeholder_metatable = {
  __index = function(t, k)
    -- Do not resolve underscore-prefixed fields
    if string.sub(k, 1, 1) == '_' then
      return nil
    end
    return new_subscript_placeholder(t, k)
  end;

  __unm = function(val)
    return new_unm_placeholder(val)
  end;

  __add = function(lhs, rhs)
    return new_add_placeholder(lhs, rhs)
  end;

  __sub = function(lhs, rhs)
    return new_sub_placeholder(lhs, rhs)
  end;

  __mul = function(lhs, rhs)
    return new_mul_placeholder(lhs, rhs)
  end;

  __div = function(lhs, rhs)
    return new_div_placeholder(lhs, rhs)
  end;

  __pow = function(lhs, rhs)
    return new_pow_placeholder(lhs, rhs)
  end;

  __mod = function(lhs, rhs)
    return new_mod_placeholder(lhs, rhs)
  end;

  __band = function(lhs, rhs)
    return new_band_placeholder(lhs, rhs)
  end;

  __bor = function(lhs, rhs)
    return new_bor_placeholder(lhs, rhs)
  end;

  __bxor = function(lhs, rhs)
    return new_bxor_placeholder(lhs, rhs)
  end;

  __bnot = function(val)
    return new_bnot_placeholder(val)
  end;

  __lshift = function(lhs, rhs)
    return new_lshift_placeholder(lhs, rhs)
  end;

  __rshift = function(lhs, rhs)
    return new_rshift_placeholder(lhs, rhs)
  end;

  __arshift = function(lhs, rhs)
    return new_arshift_placeholder(lhs, rhs)
  end;

  __rol = function(lhs, rhs)
    return new_rol_placeholder(lhs, rhs)
  end;

  __ror = function(lhs, rhs)
    return new_ror_placeholder(lhs, rhs)
  end;

  __bswap = function(val)
    return new_bswap_placeholder(val)
  end;

  __tobit = function(val)
    return new_tobit_placeholder(val)
  end;

  __tohex = function(val, n)
    return new_tohex_placeholder(val, n)
  end;
}

local packetdef_metatable = {}

local fieldresolver_metatable = {

  __index = function(field, k)
    -- Do not resolve underscore-prefixed fields
    if string.sub(k, 1, 1) == '_' then
      return nil
    end

    local type = rawget(wssdl.field_types, k)
    if type == nil then
      type = rawget(wssdl.env, k)
    end
    if type == nil then
      return nil
    end

    local fieldtype = {}
    setmetatable(fieldtype, {
      __call = function(ft, f, ...)
        -- We finished processing the packet contents ({ field : type() ... })
        -- Restore the packet definition metatable.
        setmetatable(_G, packetdef_metatable)
        return type._imbue(field, ...)
      end
    })

    -- Inside a field definition, we switch the resolver
    setmetatable(_G, {
      __index = function(t, k)
        return new_field_placeholder(k)
      end;
    })
    return fieldtype
  end;

  __len = function (field)
    if field._packet ~= nil then
      return #field._packet
    else
      return field._size
    end
  end;

}

packetdef_metatable = {

  __index = function(t, k)
    local o = {
      _name = k;

      -- Evaluate the field with concrete values
      _eval = function(field, params)
        for k, v in pairs(field) do
          field[k] = do_eval(v, params)
        end
        return field
      end
    }
    setmetatable(o, fieldresolver_metatable)
    return o
  end;

}

setmetatable(wssdl, {

  __index = function(t, k)
    if k == 'packet' then
      -- Create a new packet factory based off wssdl._packet
      local newpacket = {}
      for k, v in pairs(wssdl._packet) do newpacket[k] = v end

      local newprops = {}
      for k, v in pairs(wssdl._packet._properties) do newprops[k] = v end
      newpacket._properties = newprops
      setmetatable(newpacket, getmetatable(wssdl._packet))

      -- Switch to the packet definition metatable
      setmetatable(_G, packetdef_metatable)
      return newpacket
    end
  end;

})

make_fields = function (fields, pkt, prefix)
  local prefix = prefix or ''

  for i, field in ipairs(pkt._definition) do
    local ftype = nil
    if field._type == 'packet' then
      -- No need to deepcopy the packet definition since the parent was cloned
      local pkt = field._packet
      pkt._properties.noclone = true
      make_fields(fields, pkt, prefix .. field._name .. '.')
      ftype = ftypes.STRING
    elseif field._type == 'payload' then
      ftype = ftypes.PROTOCOL
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
        error('wssdl: Cannot compute size of primitive ' .. quote(field._name) .. ' field.')
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
          error('wssdl: Cannot compute size of primitive ' .. quote(field._name) .. ' field.')
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

function wssdl.dissector(pkt, proto)
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
        error('wssdl: Cannot evaluate size of ' .. quote(field._name) .. ' field.')
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

      if field._type ~= 'packet' then
        tree:add(protofield, rawval, val)
      end
      pktval[field._name] = val

      idx = idx + sz
    end

    return idx, pktval
  end

  return function(buf, pinfo, tree)
    local pkt = deepcopy(pkt)

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

-- Patch the bit interface to get metamethods
local oldbit = bit

bit = {}
setmetatable(bit, {
  __index = function(bit, key)
    -- Shortcut if the key doesn't exist anyway
    if oldbit[key] == nil then
      return nil
    end

    return function(x, ...)
      local mm = nil
      if key.sub(1, 1) == 'b' then
        for i, v in ipairs({x, ...}) do
          local mt = getmetatable(v)
          if mt and mt['__' .. key] then
            mm = mt['__' .. key]
            break
          end
        end
      else
        local mt = getmetatable(x)
        if mt and mt['__' .. key] then
          mm = mt['__' .. key]
        end
      end
      return (mm or oldbit[key])(x, ...)
    end
  end;

  __metatable = false;
})

return wssdl
