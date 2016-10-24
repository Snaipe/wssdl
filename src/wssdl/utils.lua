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

return utils
