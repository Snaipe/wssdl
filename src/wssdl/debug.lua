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

return debug
