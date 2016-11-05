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

local dummy = wssdl.packet {
  dummy : u32()
}

wstest.autosuite 'suffix' {

  basic = {

    pkt = wssdl.packet {
      payload : bytes();
      suffix : u32();
    };

    actual = 'aaaaaaaaaaaaaaaa' .. wstest.pack('>I4', 3149642683);

    expected = {
      payload = ByteArray.new('aaaaaaaaaaaaaaaa'),
      suffix  = 3149642683
    }

  };

  nested = {

    pkt = wssdl.packet {
      payload : bytes();
      suffix : dummy();
    };

    actual = 'aaaaaaaaaaaaaaaa' .. wstest.pack('>I4', 3149642683);

    expected = {
      payload = ByteArray.new('aaaaaaaaaaaaaaaa'),
      ['suffix.dummy'] = 3149642683
    }

  };

}
