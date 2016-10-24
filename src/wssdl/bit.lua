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
