Getting started
===============

Packet definition
-----------------

The ``packet`` function is used to define the structure of your packet.

This function takes a sequence of comma/semicolon-separated fields, with each
field using the ``<field_id> : <specifier1>(params) ... : specifierN(params)``
syntax, where ``<field_id>`` is an lua identifier for the field that is unique
in the current definition scope; and where each ``<specifier>`` is a wssdl
specifier, one of which must be a field type.

See :ref:`specifiers` for a complete list of specifiers.

.. code-block:: lua
    :name: Example

    local wssdl = require 'wssdl'

    my_pkt = wssdl.packet {
        foo : u8();
        bar : i32();
        baz : utf8(256);
    }

Creating a protocol
-------------------

A ``Proto`` object can be created by calling the ``proto(name, description)``
method on the created packet type:

.. code-block:: lua

    my_pkt = wssdl.packet { ... }

    proto = my_pkt:proto('proto_id', 'Some protocol')

The protocol name and description are passed verbatim to wireshark and as such
**must** both be unique.

Registering a dissector
-----------------------

The ``dissect`` function can be used to register one or more protocols in their
relevant dissector tables.

This function takes a sequence of dissector table mappings. Each mapping
follows the following syntax: ``<key>:<method> { <keyvalues> }``, where
``<key>`` is the identifier of the desired dissector table, ``<method>`` is either ``set`` or ``add`` (which holds the semantics of ``DissectorTable:set`` and  ``DissectorTable:add`` respectively), and ``<keyvalues>`` are key/value entries where the key is the first parameter of ``set/add`` and the value is the proto object passed as second parameter.

.. code-block:: lua
    :name: Registering a TCP protocol on port 1234

    wssdl.dissect {
      tcp.proto:add {
        [1234] = my_pkt:proto('proto_id', 'Some protocol')
      }
    }
