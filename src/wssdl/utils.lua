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

local utils = {}

utils.deepcopy = function (o)
  if type(o) == 'table' then
    local copy = {}
    for k, v in pairs(o) do
      copy[k] = utils.deepcopy(v)
    end
    setmetatable(copy, getmetatable(o))
    return copy
  else
    return o
  end
end

utils.quote = function (s)
  return '‘' .. s .. '’'
end

utils.semver = function(ver)
  ver = ver or ""
  local t, count = {}, 0
  ver:gsub("([^%.]+)", function(c)
    count = count + 1
    t[count] = tonumber(c) or 0
  end)
  t.major = t[1] or 0
  t.minor = t[2] or 0
  t.patch = t[3] or 0
  setmetatable(t, {
    __newindex = false;

    __lt = function(lhs, rhs)
      for i, v in ipairs(lhs) do
        local comp = rhs[i] or 0
        if v ~= comp then
          return v < comp
        end
      end
      return false
    end;

    __le = function(lhs, rhs)
      return lhs < rhs or lhs == rhs
    end;

    __eq = function(lhs, rhs)
      for i, v in ipairs(lhs) do
        local comp = rhs[i] or 0
        if v ~= comp then
          return false
        end
      end
      return true
    end;

    __metatable = false
  })
  return t
end

return utils
