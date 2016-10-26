local wssdl = require 'wssdl'

pkt = wssdl.packet
  : desegment() -- Required for TCP segmentation
{
  id : u32();
  data : payload(id);
}

foo = wssdl.packet {
  foo : u32();
  bar : i32();
}

wssdl.dissect {
  tcp.port:add {
    [1234] = pkt:proto('pwp', 'Packet Wrapper Protocol')
  };

  pwp.id:add {
    [1] = foo:proto('foo', 'Foo Protocol')
  }
}
