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

local wstest = {}

local debug = require 'debug'
local ws = require 'wssdl.wireshark'

local runner = Proto.new('wssdl_test', 'WSSDL Test Protocol')

local test_idx = 1
wstest.proto = function (pkt)
  test_proto_idx = test_proto_idx + 1
  return proto
end

local test_idx = 1
wstest.case = function (pkt)
  local i = test_idx
  test_idx = test_idx + 1

  local protoname = 'wssdl_test_case_' .. i
  local proto = pkt:proto(protoname, 'WSSDL Test Case ' .. i)

  local case = {
    dissects_to = function(self, actual, expected)
      local tvb = actual:tvb('WSSDL Test Buffer ' .. i)

      local res = self.dissector(tvb, wstest._pinfo, wstest._root)

      if res == 0 then
        return false, 'The payload did not match the dissector'
      end

      if res and res ~= actual:len() then
        return false, 'The dissector processed ' .. res .. ' bytes different while the buffer length is ' .. actual:len() .. ' bytes.'
      end

      if wstest._pinfo.desegment_offset > 0 or wstest._pinfo.desegment_len > 0 then
        return false, 'The dissector requested more bytes than available'
      end

      local max = 0
      for k, v in pairs(expected) do
        local name = protoname .. '.' .. k
        max = max > #name and max or #name
      end

      local diag, msg = {}, {}
      local maxe, maxa = 0, 0
      -- Compare each field
      for k, v in pairs(expected) do
        local name = protoname .. '.' .. k
        local f = self.fields[name]
        if f then
          local actual = f()

          local str_actual, str_expected = '<missing>', tostring(v)
          if actual then
            actual = actual()
            str_actual = tostring(actual)
          end

          if not actual or (type(v) == type(actual) and v ~= actual or tostring(v) ~= tostring(actual)) then
            diag[name] = {str_expected, str_actual}
            maxe = maxe > #diag[name][1] and maxe or #diag[name][1]
            maxa = maxa > #diag[name][2] and maxa or #diag[name][2]
          end
        end
      end
      for k, v in pairs(diag) do
        msg[#msg + 1] = string.format('  [%-' .. max .. 's]: Expected: %' .. maxe .. 's | Actual: %' .. maxa .. 's', k, v[1], v[2])
      end
      return #msg == 0, 'Assertion failed: \n' .. table.concat(msg, '\n')
    end;

    fields = {};

    dissector = ws.dissector(pkt, proto)
  }

  local function make_fields(prefix, pkt)
    for k, v in pairs(pkt._definition) do
      local fname = prefix .. v._name
      if v._type == 'packet' then
        make_fields(fname .. '.', v._packet)
      end
      case.fields[fname] = Field.new(fname)
    end
  end

  make_fields(protoname .. '.', pkt)

  return case
end

local ansi = {
  reset = '\027[0m';
  grey = '\027[37;2m';
  cyan = '\027[36m';
  green = '\027[32m';
  red = '\027[31m';
}

local suites = {}

wstest.suite = function (name)
  return function(tests)
    suites[name] = tests
  end
end

wstest.autosuite = function (name)
  return function(tests)
    local funcs = {}
    for k, v in pairs(tests) do
      v.pkt = wstest.case(v.pkt)
      if type(v.actual) == 'string' then
        v.actual = ByteArray.new(v.actual)
      elseif type(v.actual) == 'table' then
        v.actual = ByteArray.new(unpack(v.actual))
      end
      funcs[k] = function()
        assert(v.pkt:dissects_to(v.actual, v.expected))
      end
    end
    suites[name] = funcs
  end
end

wstest.pack = function(...) return Struct.tohex(Struct.pack(...)) end

local curlvl = 0
do
  while true do
    local info = debug.getinfo(curlvl + 1, 'Sl')
    if not info then break end
    curlvl = curlvl + 1
  end
end

local function handle_err(err, tb)
  --local tb = tb or traceback(3, 3 + curlvl)
  local tb = {}
  local err = tostring(err)
  if #tb > 0 then
    err = err .. '\n'
    for i, t in pairs(tb) do
      tb[i] = '    ' .. t
    end
    err = table.concat(tb, '\n')
  end
  return err
end

local log = {}

do
  log.levels = {
    debug = 0;
    info = 1;
    warn = 2;
    error = 3;
  }

  log.level = log.levels.info

  log.print = function(level, fmt, ...)
    if log.level <= level then
      print(fmt:format(...))
    end
  end

  for n, l in pairs(log.levels) do
    log[n] = function(...) log.print(l, ...) end
  end
end

local function traceback(level, depth)
  local tb = {}
  local level = (level or 1) + 1
  while true do
    local info = debug.getinfo(level, 'Sl')
    if not info then break end
    if info.what == 'C' then
      tb[#tb + 1] = '<native>'
    else
      tb[#tb + 1] = string.format('%s:%d',
          info.source:sub(1,1) == '@' and info.source:sub(2) or info.source,
          info.currentline)
    end
    level = level + 1
  end
  while depth and depth > 0 do
    tb[#tb] = nil
    depth = depth - 1
  end
  return tb
end

runner.dissector = function (tvb, pinfo, root)
  local status = 0
  local failed, passed  = 0, 0

  wstest._pinfo = pinfo

  for name, suite in pairs(suites) do
    local nbtests = 0
    for _,_ in pairs(suite) do
      nbtests = nbtests + 1
    end
    if nbtests > 0 then
      log.info('[' .. ansi.cyan .. '⚙' .. ansi.reset ..'] ' .. name .. ': running ' .. nbtests .. ' tests')

      for name, test in pairs(suite) do
        log.info('[' .. ansi.cyan .. '⚙' .. ansi.reset ..'] ' .. name .. ': started')

        tree = root:add(runner)
        tree:set_hidden()
        wstest._root = tree

        pinfo.desegment_offset = 0
        pinfo.desegment_len = 0

        local ok, err, res = xpcall(function () test(pinfo, tree) end, function(e) return handle_err(e, {}) end)
        local level, color, prefix
        if ok then
          level, color, prefix = log.levels.info, ansi.green, '✓'
          passed = passed + 1
        else
          level, color, prefix = log.levels.error, ansi.red, '✗'
          failed = failed + 1
        end

        log.print(level, '[' .. color .. prefix .. ansi.reset ..'] %s: %s',
            name, ok and 'OK' or 'KO')

        if not ok then
          local pref = '[' .. ansi.grey .. '-' .. ansi.reset ..'] '
          log.error(pref .. err:gsub('\n', '\n' .. pref))
        end
      end
    end
  end

  local level, color, prefix
  if failed == 0 then
    level, color, prefix = log.levels.info, ansi.green, '✓'
  else
    level, color, prefix = log.levels.error, ansi.red, '✗'
    status = 1
  end

  log.print(level, '[' .. color .. prefix .. ansi.reset ..'] %s: %d passed, %d failed',
      status == 0 and 'OK' or 'KO', passed, failed)

  os.exit(status)
end

-- Use the test runner on the test PCAP (empty UDP packet on port 65535)
DissectorTable.get('udp.port'):set(65535, runner)

local function list_tests(directory)
  local i, t, popen = 0, {}, io.popen
  local pfile = popen('ls "' .. directory .. '"')
  for filename in pfile:lines() do
    if string.sub(filename, -4) == '.lua' then
      i = i + 1
      t[i] = filename
    end
  end
  pfile:close()
  return t
end

local t = list_tests('tests')

local function dotestfile(path)
  local chunk = loadfile(path)
  local setfenv = debug.setfenv or function(f, env) debug.setupvalue(f, 1, env) end
  local newenv = {}
  for k, v in pairs(_G) do newenv[k] = v end
  newenv._G = newenv
  newenv.wstest = wstest
  setfenv(chunk, newenv)
  chunk()
end

for _, k in pairs(t) do
  local ok, err = xpcall(function () dotestfile('tests/' .. k) end, handle_err)

  if not ok then
    log.error(err)
    os.exit(1)
  end
end

return wstest
