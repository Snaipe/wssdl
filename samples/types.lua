local wssdl = require 'wssdl'

-- Types supported by wssdl

wssdl.packet {
  u8     : u8();      -- Unsigned 8-bit integer
  u16    : u16();     -- Unsigned 16-bit integer
  u24    : u24();     -- Unsigned 24-bit integer
  u32    : u32();     -- Unsigned 32-bit integer
  u64    : u64();     -- Unsigned 64-bit integer

  i8     : i8();      -- Signed 8-bit integer
  i16    : i16();     -- Signed 16-bit integer
  i24    : i24();     -- Signed 24-bit integer
  i32    : i32();     -- Signed 32-bit integer
  i64    : i64();     -- Signed 64-bit integer

  int    : int(4);    -- Unsigned 4-bit integer
  uint   : uint(4);   -- Unsigned 4-bit integer

  f32    : f32();     -- 32-bit floating-point value
  f64    : f64();     -- 32-bit floating-point value

  utf8   : utf8(20);  -- UTF8-encoded string w/ a length of 20 octets
  utf8z  : utf8z();   -- Null-terminated UTF8-encoded string
  utf16  : utf16(20); -- UTF16-encoded string w/ a length of 20 16-bit word
  utf16z : utf16z();  -- Null-terminated UTF16-encoded string

  bytes  : bytes(20); -- Byte buffer with a size of 20 octets
  bits   : bits(3);   -- Bits buffer with a size of 3 bits
  bool   : bool(3);   -- Boolean value with a size of 3 bits (0 = False, !0 = True)
  bool2  : bool();    -- No size means 1 bit
  bit    : bit();     -- A single bit

  ipv4   : ipv4();    -- IPv4 address
  ipv6   : ipv6();    -- IPv4 address

  -- Using :le() on supported types means Little-Endian
  le_u32 : u32():le();
}

-- Payload type

wssdl.packet {
  kind   : u32();

  -- Packet payload using the `kind` field as dissection criterion,
  -- using the dissector table identified by '<proto>.kind'.
  data   : payload { kind };
}

wssdl.packet {
  kind   : u32();

  -- Packet payload using the `kind` field as dissection criterion, and
  -- using the dissector table identified by 'custom.key'
  data   : payload { kind, 'custom.key' };
}

wssdl.packet {
  kind   : u32();
  len    : u32();

  -- Packet payload using the `kind` field as dissection criterion, with a
  -- total size specified by the contents of len.
  data   : payload { kind, nil, len };
}

-- UI specifiers

wssdl.packet {
  foo : u8()
      : name('Foo')
      : description('A field containing the concept of Foo');

  -- Display the field in hexadecimal form
  hex : u32()
      : hex();

  -- Display the field in octal form
  oct : u32()
      : oct();
}
