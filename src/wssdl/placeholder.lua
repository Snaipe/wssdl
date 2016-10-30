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

local specifiers = require 'wssdl.specifiers'
local utils      = require 'wssdl.utils'
local debug      = require 'wssdl.debug'

-- Module
local placeholder = {}

local wssdl = nil
placeholder.init = function (self, mod)
  wssdl = mod
  return self
end

local placeholder_metatable = {}

local do_eval = function (v, values)
  if type(v) == 'table' and v._eval ~= nil then
    return v:_eval(values)
  else
    return v
  end
end
placeholder.do_eval = do_eval

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

placeholder.metatable = function(defenv, packetdef_metatable, make_pktfield)
  return {
    __index = function(field, k)
      -- Do not resolve underscore-prefixed fields
      if string.sub(k, 1, 1) == '_' then
        return nil
      end

      if field._name:sub(1,1) == '_' then
        error('wssdl: Invalid identifier for field ' .. utils.quote(field._name) .. ': Fields must not start with an underscore', 3)
      end
      if wssdl._current_def[field._name] ~= nil then
        error('wssdl: Duplicate field ' .. utils.quote(field._name) .. ' in packet definition.', 3)
      end

      wssdl._current_def[field._name] = field

      local type = rawget(specifiers.field_types, k)
      if type == nil then
        type = rawget(wssdl.env, k)
      end
      if type == nil then
        type = debug.find_local(3, k)
      end
      if type == nil then
        return nil
      end

      -- Strip locals from previous field definitions
      local locals = utils.copy(wssdl._locals)
      for k, v in pairs(wssdl._current_def) do
        -- Don't strip internal fields from the locals
        if k:sub(1,1) ~= '_' then
          for i = 1, #locals do
            local l = wssdl._locals[i]
            if l and l[1] == k then
              wssdl._locals[i] = nil
            end
          end
        end
      end

      local fieldtype = {}
      setmetatable(fieldtype, {
        __call = function(ft, f, ...)
          -- We finished processing the packet contents ({ field : type() ... })
          -- Restore the packet definition metatable.
          local env = setmetatable({}, packetdef_metatable)
          debug.setfenv(wssdl.fenv, env)
          -- The user environment is 3 stack levels up
          wssdl._locals = locals
          debug.reset_locals(3, nil, make_pktfield)
          return type._imbue(field, ...)
        end
      })

      local pktdef = field._pktdef

      local env = setmetatable({}, {
        __index = function(t, k)
          if pktdef[k] == nil then
            error('wssdl: Unknown symbol ' .. utils.quote(k) .. '.', 2)
          end
          return new_field_placeholder(k)
        end;
      })

      -- Inside a field definition, we switch to the resolver context
      debug.setfenv(wssdl.fenv, env)
      -- The user environment is 3 stack levels up
      debug.reset_locals(3, nil, function(ctx, n) return new_field_placeholder(n) end)
      debug.set_locals(3, wssdl._locals)

      return fieldtype
    end;

    __len = function (field)
      local packet = rawget(field, '_packet')
      if packet ~= nil then
        return #packet
      else
        return field._size
      end
    end;
  }
end

return placeholder
