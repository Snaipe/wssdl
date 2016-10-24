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

local type_specifier = function (type, basesz)
  local o = {
    _imbue = function (field, s)
      field._size = s * basesz
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
    _imbue = function(field, sz)
      if nullterm then
        field._size = 0
      else
        field._size = size * basesz
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

  utf8   = string_type(1, false);
  utf8z  = string_type(1, true);
  utf16  = string_type(2, false);
  utf16z = string_type(2, true);

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

return specifiers
