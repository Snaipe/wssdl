local wssdl = require("wssdl"):init(_ENV)

foo = wssdl.packet
{
  foo : u32();
  bar : f64();
  baz : utf8z();
}

DissectorTable.get('udp.port')
    :set(5005, foo:protocol('foo', 'Foo Protocol'))
