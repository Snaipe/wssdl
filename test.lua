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

tcp = wssdl.packet
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

custom_proto = tcp:protocol('custom_tcp', 'custom tcp header')
DissectorTable.get("udp.port"):add(5005, custom_proto)
