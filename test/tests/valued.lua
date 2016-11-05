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

wstest.autosuite 'valued' {

  simple = {

    pkt = wssdl.packet {
      bytes : bytes();
      val : u8() : value(1)
    };

    actual = 'aaaaaaaa01';
    expected = { bytes = ByteArray.new('aaaaaaaa') }

  };

  suffix = {

    pkt = wssdl.packet {
      bytes : bytes();
      before : u8();
      val : u8() : value(1);
      after : u8();
    };

    actual = 'aaaaaaaabb01cc';

    expected = {
      bytes = ByteArray.new('aaaaaaaa'),
      before = 0xbb,
      after = 0xcc
    }

  };

  multiple = {

    pkt = wssdl.packet {
      before : bytes();
      val : u8() : value(1);
      after : bytes();
    };

    actual = 'aaaaaaaa01cccccccc';

    expected = {
      before = ByteArray.new('aaaaaaaa'),
      after  = ByteArray.new('cccccccc'),
    };

  };

}
