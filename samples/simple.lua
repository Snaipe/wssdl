local wssdl = require("wssdl"):init(_ENV)

foo = wssdl.packet
{
  foo : u32();
  bar : f64();
  baz : stringz();
}

DissectorTable.get('udp.port')
    :set(1234, foo:protocol('foo', 'Foo Protocol'))
