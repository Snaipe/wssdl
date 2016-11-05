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

local specifiers = {}

local utils = require 'wssdl.utils'

local type_specifier = function (type, basesz)
  local o = {
    _imbue = function (field, s)
      if s then
        field._size = s * basesz
      else
        field._size = nil
      end
      field._type = type
      return field
    end
  }
  return o
end

local type_specifier_sized = function (type, size)
  local o = {
    _imbue = function (field)
      field._size = size
      field._type = type
      return field
    end
  }
  return o
end

local string_type = function(basesz, nullterm)
  return {
    _imbue = function(field, size)
      if nullterm then
        field._size = 0
      else
        field._size = size * basesz * 8
      end
      field._type = "string"
      field._basesz = basesz
      return field
    end
  }
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

specifiers.field_types = {
  bits  = type_specifier("bits",      1);
  bytes = type_specifier("bytes",     8);
  int   = type_specifier("signed",    1);
  uint  = type_specifier("unsigned",  1);

  bit = type_specifier_sized("bits", 1);

  i8  = type_specifier_sized("signed", 8);
  i16 = type_specifier_sized("signed", 16);
  i24 = type_specifier_sized("signed", 24);
  i32 = type_specifier_sized("signed", 32);
  i64 = type_specifier_sized("signed", 64);

  u8  = type_specifier_sized("unsigned", 8);
  u16 = type_specifier_sized("unsigned", 16);
  u24 = type_specifier_sized("unsigned", 24);
  u32 = type_specifier_sized("unsigned", 32);
  u64 = type_specifier_sized("unsigned", 64);

  f32 = type_specifier_sized("float", 32);
  f64 = type_specifier_sized("float", 64);

  ipv4 = type_specifier_sized("address", 32);
  ipv6 = type_specifier_sized("address", 128);

  utf8   = string_type(1, false);
  utf8z  = string_type(1, true);
  utf16  = string_type(2, false);
  utf16z = string_type(2, true);

  le = {
    _imbue = function (field)
      local t = field._type
      if t == 'address' and field._size == 128 then
        error('wssdl: Field type can\'t be parsed as Little-Endian', 2)
      end
      if t == 'signed' or t == 'unsigned' or t == 'float' or t == 'address'
          or (t == 'string' and field._basesz == 2) then
        if type(field._size) ~= 'number' then
          field._le = true
        else
          if field._size > 64 then
            error('wssdl: Little-Endian fields larger than 64-bits aren\'t supported by Wireshark.', 2)
          end
          if field._size % 8 > 0 then
            error('wssdl: Endianness only makes sense for sizes divisible by 8.', 2)
          end
          if field._size <= 8 then
            error('wssdl: Endianness only makes sense for multiple octets.', 2)
          end
          field._le = true
        end
      else
        error('wssdl: Field type can\'t be parsed as Little-Endian', 2)
      end
      return field
    end
  };

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

      if #criterion == 0 then
        error('wssdl: Field ' .. utils.quote(field._name) .. ' needs a dissection criterion.', 2)
      end

      -- Check if the criterion refers to a real field
      local path = criterion[1]
      local f = field._pktdef[criterion[1]]
      if f and #criterion > 1 then
        f = f._packet
      end
      for i = 2, #criterion do
        local v = criterion[i]
        if f then
          local idx = f._lookup[v]
          if idx then
            if i < #criterion then
              f = rawget(f._definition[idx], '_packet')
            end
          else
            f = nil
          end
        end
        path = path .. '.' .. v
      end

      if not f then
        error('wssdl: Dissection criterion ' .. utils.quote(path) ..
              ' does not match a real field.', 2)
      end

      -- Check if the type is valid
      local validt = { unsigned = true, bits = true, string = true }
      if not validt[f._type] then
        error('wssdl: Dissection criterion ' .. utils.quote(path) ..
              ' must be an unsigned integer or a string.', 2)
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

  align = {
    _imbue = function(field, val)
      field._align = val
      return field
    end
  };

  value = {
    _imbue = function(field, val)
      field._value = val
      return field
    end
  };

  accept = {
    _imbue = function(field, ...)
      field._accept = field._accept or {}
      for _, p in ipairs({...}) do
        if type(p) == 'function' then
          field._accept[#field._accept + 1] = p
        else
          field._accept[#field._accept + 1] = function(e) return type(e) == type(p) and p == e end
        end
      end
      return field
    end
  };

  reject = {
    _imbue = function(field, ...)
      field._reject = field._reject or {}
      for _, p in ipairs({...}) do
        if type(p) == 'function' then
          field._reject[#field._reject + 1] = function(e) return not p(e) end
        else
          field._reject[#field._reject + 1] = function(e) return type(e) ~= type(p) or p ~= e end
        end
      end
      return field
    end
  };
}

return specifiers
