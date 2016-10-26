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

local debug = {}

local luadebug = require 'debug'

debug.print = function(tbl, indent)
  if not indent then indent = 0 end
  if type(tbl) == 'table' then
    for k, v in pairs(tbl) do
      local formatting = string.rep("  ", indent) .. "[" .. tostring(k) .. "]: "
      if type(v) == "table" then
        print(formatting)
        debug.print(v, indent+1)
      elseif type(v) == 'string' then
        print(formatting .. v)
      else
        print(formatting .. tostring(v))
      end
    end
  else
    print(string.rep("  ", indent) .. tostring(tbl))
  end
end

debug.setfenv = setfenv or function (fn, env)
  local i = 1
  while true do
    if type(fn) == 'number' then
      fn = luadebug.getinfo(fn).func
    end
    local name = luadebug.getupvalue(fn, i)
    if name == '_ENV' then
      luadebug.upvaluejoin(fn, i, (function()
        return env
      end), 1)
      break
    elseif not name then
      break
    end

    i = i + 1
  end

  return fn
end

debug.getfenv = getfenv or function (fn, env)
  local i = 1
  while true do
    if type(fn) == 'number' then
      fn = luadebug.getinfo(fn).func
    end
    local name, val = luadebug.getupvalue(fn, i)
    if name == '_ENV' then
      return val
    elseif not name then
      break
    end
    i = i + 1
  end
end

return debug
