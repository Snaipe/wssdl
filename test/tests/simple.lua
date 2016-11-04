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

wstest.autosuite 'simple' {

  primitive = {
    pkt = wssdl.packet {
      u8    : u8();
      u16   : u16();
      u24   : u24();
      u32   : u32();
      u64   : u64();
      i8    : i8();
      i16   : i16();
      i24   : i24();
      i32   : i32();
      i64   : i64();
      f32   : f32();
      f64   : f64();
      utf8  : utf8(5);
      utf8z : utf8z();
    };

    actual = wstest.pack('>I1 I2 I3 I4 E' ..
                          'i1 i2 i3 i4 e' ..
                          'f  d   c5  s',
      1, 2, 3, 4, UInt64.new(5),
      1, 2, 3, 4, Int64.new(5),
      3.140000104904175, 3.14000000000000012434497875802E0,
      'Hello', 'World!');

    expected = {
      u8 = 1, u16 = 2, u24 = 3, u32 = 4, u64 = UInt64.new(5),
      i8 = 1, i16 = 2, i24 = 3, i32 = 4, i64 = Int64.new(5),
      f32 = 3.140000104904175, f64 = 3.14000000000000012434497875802E0,
      utf8 = 'Hello', utf8z = 'World!'
    };
  };

  bitfield = {
    pkt = wssdl.packet {
      b1 : bit();
      b2 : uint(2);
      b3 : int(3);
      b4 : bits(2);
    };

    actual = 'aa'; -- 1 01 010 10

    expected = { b1 = 1, b2 = 1, b3 = 2, b4 = 2 }
  };

  unaligned = {
    pkt = wssdl.packet {
      unused : bit(); -- make things complicated

      u8    : u8();
      u16   : u16();
      u24   : u24();
      u32   : u32();
      u64   : u64();
      i8    : i8();
      i16   : i16();
      i24   : i24();
      i32   : i32();
      i64   : i64();
      f32   : f32();
      f64   : f64();
    };

    -- This is actually the buffer from 'primitive' (without strings)
    -- right-shifted by 1 and padded by one zero-byte before and after
    actual = '0080010000018000000200000000000000028080010000018'
          .. '00000020000000000000002a0247ae1a0048f5c28f5c28f80';

    expected = {
      u8 = 1, u16 = 2, u24 = 3, u32 = 4, u64 = UInt64.new(5),
      i8 = 1, i16 = 2, i24 = 3, i32 = 4, i64 = Int64.new(5),
      f32 = 3.140000104904175, f64 = 3.14000000000000012434497875802E0
    };

  };

}
