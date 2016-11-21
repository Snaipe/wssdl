.. _specifiers:

Specifier reference
===================

Primitive Field Types
---------------------

.. tabularcolumns:: |p{2cm}|L|

============ ===================================================================
Type         Description
============ ===================================================================
``u8()``     Unsigned 8-bit integer.
------------ -------------------------------------------------------------------
``u16()``    Unsigned 16-bit integer.
------------ -------------------------------------------------------------------
``u24()``    Unsigned 24-bit integer.
------------ -------------------------------------------------------------------
``u32()``    Unsigned 32-bit integer.
------------ -------------------------------------------------------------------
``u64()``    Unsigned 64-bit integer.
------------ -------------------------------------------------------------------
``i8()``     Signed 8-bit integer.
------------ -------------------------------------------------------------------
``i16()``    Signed 16-bit integer.
------------ -------------------------------------------------------------------
``i24()``    Signed 24-bit integer.
------------ -------------------------------------------------------------------
``i32()``    Signed 32-bit integer.
------------ -------------------------------------------------------------------
``i64()``    Signed 64-bit integer.
------------ -------------------------------------------------------------------
``int(N)``   Unsigned ``N``-bit integer. If ``N`` isn't specified, the size of
             the field becomes the remaining payload size.
             ``N`` cannot be larger than 64-bits.
------------ -------------------------------------------------------------------
``uint(N)``  Unsigned ``N``-bit integer. If ``N`` isn't specified, the size of
             the field becomes the remaining payload size.
             ``N`` cannot be larger than 64-bits.
------------ -------------------------------------------------------------------
``f32()``    32-bit floating-point value.
------------ -------------------------------------------------------------------
``f64()``    64-bit floating-point value.
------------ -------------------------------------------------------------------
``utf8(N)``  UTF8-encoded string w/ a length of ``N`` code units. If ``N``
             isn't specified, the size of the field becomes the remaining
             payload size.
             If used, the field must be aligned on an octet boundary.
------------ -------------------------------------------------------------------
``utf8z()``  Null-terminated UTF8-encoded string.
             If used, the field must be aligned on an octet boundary.
------------ -------------------------------------------------------------------
``utf16(N)`` UTF16-encoded string w/ a length of ``N`` code units. If ``N``
             isn't specified, the size of the field becomes the remaining
             payload size.
             If used, the field must be aligned on an octet boundary.
------------ -------------------------------------------------------------------
``utf16z()`` Null-terminated UTF16-encoded string.
             If used, the field must be aligned on an octet boundary.
------------ -------------------------------------------------------------------
``bytes(N)`` Byte buffer with a size of ``N`` octets. If ``N`` isn't specified,
             the size of the field becomes the remaining payload size.
             If used, the field must be aligned on an octet boundary.
------------ -------------------------------------------------------------------
``bits(N)``  Bits buffer with a size of ``N`` bits.
             ``N`` cannot be larger than 64-bits.
------------ -------------------------------------------------------------------
``bool(N)``  Boolean value with a size of ``N`` bits. If ``N`` isn't specified
             the size of this field is 1 bit.
             A field value of zero means False, while non-zero means True.
------------ -------------------------------------------------------------------
``bit()``    A single bit.
------------ -------------------------------------------------------------------
``ipv4()``   IPv4 address.
             If used, the field must be aligned on an octet boundary.
------------ -------------------------------------------------------------------
``ipv6()``   IPv6 address.
             If used, the field must be aligned on an octet boundary.
------------ -------------------------------------------------------------------
``ether()``  Ethernet address.
             If used, the field must be aligned on an octet boundary.
============ ===================================================================

Special Field Types
-------------------

User Types
~~~~~~~~~~

Any variable declared with ``wssdl.packet`` can be used as a field type.

Payload Type
~~~~~~~~~~~~

``payload(<criterion>, [size])``

The special payload type is used for packets that contains data that needs to
be subdissected by another registered dissector.

The ``<criterion>`` parameter is either a field, or a 2-element table containing
a field and a key:

* ``payload(<field>, [size])``

* ``payload({ <field>, <key> }, [size])``

``<field>`` is the field that should be used as the value to lookup the
dissector table entry, ``<key>`` is the dissector table identifier.

If ``<key>`` is nil or unspecified, then the dissector table identifier becomes
``<prototype name>.<field>``.

``<size>`` is an optional parameter representing the size of the field in octets.

If ``<size>`` is nil or unspecified, then the size of the field becomes the
remaining packet size.

Other specifiers
----------------

.. tabularcolumns:: |p{4cm}|L|

==================== ===========================================================
Type                 Description
==================== ===========================================================
``le()``             Parse the field as little-endian. The following types
                     support little-endian: u8, u16, u24, u32, u64, i8, i16,
                     i24, i32, i64, int, uint, f32, f64, utf16, utf16z, ipv4.
-------------------- -----------------------------------------------------------
``dec()``            Use a decimal format for the integer field (default)
-------------------- -----------------------------------------------------------
``hex()``            Use a hexadecimal format for the integer field
-------------------- -----------------------------------------------------------
``oct()``            Use an octal format for the integer field
-------------------- -----------------------------------------------------------
``name(str)``        Set the display name of the field to ``str``.
-------------------- -----------------------------------------------------------
``description(str)`` Set the description of the field to ``str``.
==================== ===========================================================
