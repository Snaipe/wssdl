# 🝰 wssdl

[![Build Status](https://api.travis-ci.org/diacritic/wssdl.svg?branch=master)](https://travis-ci.org/diacritic/wssdl/builds) 
[![License (GPL)](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://github.com/diacritic/wssdl/blob/master/LICENSE) 
[![Version (Experimental)](https://img.shields.io/github/release/diacritic/wssdl.svg?label=version)](https://github.com/diacritic/wssdl/releases/latest) 
[![Language (Lua)](https://img.shields.io/badge/powered_by-Lua-brightgreen.svg)](https://lua.org) 
[![Gitter chat](https://badges.gitter.im/diacritic/wssdl.png)](https://gitter.im/diacritic/wssdl) 

Wireshark-Specific Dissector Language

```lua
wssdl.packet {
  message     : u8();
  definition  : i32();
  done        : utf8z();
  easy        : ipv4();
}
```

## What is this?

wssdl is a domain specific language on top of lua built for the
purpose of expressing easily message dissectors.

## Documentation

| Stable | Latest |
| --- | --- |
[![Stable docs][doc-stable-badge]][doc-stable] | [![Latest docs][doc-latest-badge]][doc-latest]

Also check out some of the [samples][samples].

## Install

### From the release

Grab the bootstrapped `wssdl.lua` from the [latest release][latest],
and put it in your Wireshark Plugin directory
(usually ~/.config/wireshark/plugins or /usr/lib/wireshark/<version>)

### From source

The build toolchain needs lua 5.1 or newer, luarocks and the luafilesystem
module.

Clone this repository, and from the root directory call `make install`
to install it to `~/.config/wireshark/plugins`, or
`make WS_PLUGIN_DIR=/your/path install` to install it to the path of your choice.

[latest]: https://github.com/diacritic/wssdl/releases/latest
[samples]: https://github.com/diacritic/wssdl/tree/master/samples

[doc-stable]:       http://wssdl.readthedocs.io/en/stable/?badge=stable
[doc-latest]:       http://wssdl.readthedocs.io/en/latest/?badge=latest
[doc-stable-badge]: https://readthedocs.org/projects/wssdl/badge/?version=stable
[doc-latest-badge]: https://readthedocs.org/projects/wssdl/badge/?version=latest
