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
--

require 'luarocks.loader'

local fs = require 'lfs'

local args = {...}
local root = args[1]:gsub('/$', ''):gsub('\\$', '')

function scandir(root, path)
  local files = {}
  -- adapted from http://keplerproject.github.com/luafilesystem/examples.html
  path = path or ''
  for file in fs.dir(root..path) do
    if file ~= '.' and file ~= '..' then
      local f = path .. '/' .. file
      local attr = lfs.attributes(root..f)
      assert(type(attr) == 'table')
      if attr.mode == 'directory' then
        scandir(root, f)
      else
        if file:find('%.lua$') then
          hndl = (f:gsub('%.lua$', '')
              :gsub('/', '.')
              :gsub('\\', '.')
              :gsub('^%.', '')
            ):gsub('%.init$', '')
          files[hndl] = io.open(root..f):read('*a')
              :gsub(' *%-%-[^\n]*\n', '')
        end
      end
    end
  end
  return files
end

local files = scandir(root)

acc = { [[
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
--
]] }

local wrapper = { '\n--------------------------------------\npackage.preload[\'', nil, '\'] = function (...)\n', nil, '\nend\n' }

for k,v in pairs( files ) do
  wrapper[2], wrapper[4] = k, v
  table.insert(acc, table.concat(wrapper))
end

table.insert(acc, [[
-----------------------------------------------

do
  if not package.__loadfile then
    local original_loadfile = loadfile
    local function lf(file)
      local hndl = file:gsub('%.lua$', '')
                       :gsub('/', '.')
                       :gsub('\\', '.')
                       :gsub('%.init$', '')
      return package.preload[hndl] or original_loadfile(name)
    end

    function dofile(name)
      return lf(name)()
    end

    loadfile, package.__loadfile = lf, loadfile
  end
end

return require 'wssdl-core'
]])

print(table.concat(acc))
