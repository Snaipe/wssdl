local wssdl = require "wssdl"

tcp_flags = wssdl.packet
{
  ns  = wssdl.bit,
  cwr = wssdl.bit,
  ece = wssdl.bit,
  urg = wssdl.bit,
  ack = wssdl.bit,
  psh = wssdl.bit,
  rst = wssdl.bit,
  syn = wssdl.bit,
  fin = wssdl.bit,
}

tcp_options = wssdl.packet
  : padded(32)
{
}

tcp = wssdl.packet
{
  src_port    = wssdl.u16,
  dst_port    = wssdl.u16,
  seq_num     = wssdl.u32,
  ack_num     = wssdl.u32,
  data_offset = wssdl.uint(4),
  reserved    = wssdl.bits(3),
  flags       = tcp_flags,
  window_size = wssdl.u16,
  options     = tcp_options,
}
