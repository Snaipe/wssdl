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

debug.print = function(tbl, indent, depth)
  local depth = depth or 3
  if depth == 0 then
    print(string.rep("  ", indent) .. '<snip>')
    return
  end
  if not indent then indent = 0 end
  if type(tbl) == 'table' then
    for k, v in pairs(tbl) do
      local formatting = string.rep("  ", indent) .. "[" .. tostring(k) .. "]: "
      if type(v) == "table" then
        print(formatting)
        debug.print(v, indent+1, depth - 1)
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

if getfenv then
  debug.getfenv = function (fn, env)
    local env = getfenv(fn, env)
    return env, type(fn) == 'number' and luadebug.getinfo(fn).func or fn
  end
else
  debug.getfenv = function (fn, env)
    if type(fn) == 'number' then
      fn = luadebug.getinfo(fn).func
    end
    local i = 1
    while true do
      local name, val = luadebug.getupvalue(fn, i)
      if name == '_ENV' then
        return val, fn
      elseif not name then
        break
      end
      i = i + 1
    end
  end
end

debug.traceback = function ()
  local level = 1
  while true do
    local info = luadebug.getinfo(level, "Sl")
    if not info then break end
    if info.what == "C" then
      print(level, "<native>")
    else
      print(level, string.format("[%s]:%d", info.short_src, info.currentline))
    end
    level = level + 1
  end
end

debug.find_local = function(lvl, n)
  local i = 1

  -- Search locals at specified stack level
  while true do
    local name, val = luadebug.getlocal(lvl, i)
    if not name then
      break
    end
    if name == n then
      return val
    end
    i = i + 1
  end

  -- Search upvalues at specified stack level
  i = 1
  while true do
    local name, val = luadebug.getupvalue(lvl, i)
    if not name then
      break
    end
    if name == n then
      return val
    end
    i = i + 1
  end
  return nil
end

debug.get_locals = function(lvl)
  local locals = {}
  local i = 1
  while true do
    local name, val = luadebug.getlocal(lvl, i)
    if not name then
      break
    end
    if name ~= '(*temporary)' then
      locals[i] = { name, val }
    end
    i = i + 1
  end
  return locals
end

debug.set_locals = function(lvl, locals)
  local i = 1
  while true do
    if locals[i] == nil then
      break
    end
    local name = luadebug.setlocal(lvl, i, locals[i][2])
    if not name then
      break
    end
    i = i + 1
  end
end

debug.reset_locals = function(lvl, ctx, fn)
  local locals = debug.get_locals(lvl + 1)
  for i = 1, #locals do
    local o = fn(ctx, locals[i][1])
    local name = luadebug.setlocal(lvl, i, o)
    if not name then
      break
    end
  end
end

return debug
