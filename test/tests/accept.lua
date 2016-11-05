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

local wssdl = require 'wssdl'

wstest.autosuite 'accept' {

  accept_val = {

    rejected = false;

    pkt = wssdl.packet {
      dummy : u8() : accept(1)
    };

    actual = '01';
    expected = {}

  };

  reject_val = {

    rejected = true;

    pkt = wssdl.packet {
      dummy : u8() : reject(1)
    };

    actual = '01';
    expected = {}

  };

  accept_func = {

    rejected = false;

    pkt = wssdl.packet {
      dummy : u8() : accept(function(e) return e == 1 end)
    };

    actual = '01';
    expected = {}

  };

  reject_func = {

    rejected = true;

    pkt = wssdl.packet {
      dummy : u8() : reject(function(e) return e == 1 end)
    };

    actual = '01';
    expected = {}

  };

  accept_mixed = {

    rejected = false;

    pkt = wssdl.packet {
      dummy : u8() : accept(2, function(e) return e == 1 end)
    };

    actual = '01';
    expected = {}

  };

  reject_mixed = {

    rejected = true;

    pkt = wssdl.packet {
      dummy : u8() : reject(2, function(e) return e == 1 end)
    };

    actual = '02';
    expected = {}

  };

  accept_chained_1 = {

    rejected = false;

    pkt = wssdl.packet {
      dummy : u8() : accept(2)
                   : accept(function(e) return e == 1 end)
    };

    actual = '01';
    expected = {}

  };

  accept_chained_2 = {

    rejected = false;

    pkt = wssdl.packet {
      dummy : u8() : accept(2)
                   : accept(function(e) return e == 1 end)
    };

    actual = '02';
    expected = {}

  };

  reject_chained_1 = {

    rejected = true;

    pkt = wssdl.packet {
      dummy : u8() : reject(2)
                   : reject(function(e) return e == 1 end)
    };

    actual = '01';
    expected = {}

  };

  reject_chained_2 = {

    rejected = true;

    pkt = wssdl.packet {
      dummy : u8() : reject(2)
                   : reject(function(e) return e == 1 end)
    };

    actual = '02';
    expected = {}

  };

}
