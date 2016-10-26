-- In this sample, we'll use the DSL to describe what a TCP packet looks like
-- and use the generated dissector in place of the builtin one.
--
-- NOTE: This is a bad idea to do in practice since wireshark expects its
-- own TCP dissector and might start behaving weirdly or crash.
--
-- This isn't an extensive replacement for the builtin TCP dissector, it
-- simply shows that we can handle more complex packet definitions.
--
local wssdl = require 'wssdl'

tcp_flags = wssdl.packet
{
  ns  : bit();
  cwr : bit();
  ece : bit();
  urg : bit();
  ack : bit();
  psh : bit();
  rst : bit();
  syn : bit();
  fin : bit();
}

tcp_hdr = wssdl.packet
  : padding(32)
{
  src_port    : u16();
  dst_port    : u16();
  seq_num     : u32();
  ack_num     : u32();
  data_offset : bits(4);
  reserved    : bits(3);
  flags       : tcp_flags();
  window_size : u16();
  checksum    : u16();
  urgent_ptr  : u16();

  -- The options field takes the remaining space before the payload.
  -- Since data_offset contains the offset from the start of the packet
  -- to the payload in 32-bit words (i.e. 4 bytes), and the minimum size
  -- of the header is 160 bits (i.e. 5 32-bit words), the size of the
  -- options field is (data_offset - 5) * 4 bytes.
  options     : bytes((data_offset - 5) * 4);
}

tcp = wssdl.packet
{
  header  : tcp_hdr();
  payload : payload { header.dst_port, 'tcp.port' };
}

wssdl.dissect {
  -- Let's replace the builtin dissector for TCP!
  ip.proto:set {
    [0x06] = tcp:proto('wssdl_TCP', 'Transmission Control Protocol (wssdl)')
  }
}
