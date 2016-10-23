local wssdl = require "wssdl"

wssdl:init(_ENV)

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
  options     : bytes((data_offset - 5) * 4);
}

tcp = wssdl.packet
{
  header  : tcp_hdr();
  payload : payload { header.dst_port, 'tcp.port' };
}

-- Let's replace the builtin dissector for TCP!
DissectorTable.get('ip.proto')
    :set(0x06, tcp:protocol('TCP', 'Transmission Control Protocol'))
