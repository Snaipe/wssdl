local wssdl = require 'wssdl'

foo = wssdl.packet
{
  foo : u32();
  bar : f64();
  baz : utf8z();
}

wssdl.dissect {
  udp.port:set {
    [5005] = foo:proto('foo', 'Foo Protocol')
  }
}
