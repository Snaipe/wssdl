How definitions are parsed
==========================

The parsing process
-------------------

A packet definition always contain zero or more fields, called *prefix* fields,
followed optionally by one field with unspecified size, called *variadic* field,
followed by zero or more end fields, called *suffix* fields.

1. Prefix fields are parsed first, top-to-bottom, until the end of
   the packet is reached or a variadic field is reached.
2. If a variadic field is reached, it is skipped and the parser jumps to the
   last suffix field.
3. All suffix fields are parsed, bottom-to-top, until the variadic field is
   reached again.
4. The variadic field is parsed, with a size equal to the gap between the last
   prefix field and the first suffix field.

.. code-block:: none

    parsing order         1   2   3

    packet {
        [prefix field 1]  _
              . . .       | forward parsing
        [prefix field N]  v   .
                              .
        [variadic field]  .   .   |-> forward parsing
                          .
        [suffix field 1]  .   ^
              . . .       .   | reverse parsing
        [suffix field N]  .   ¯
    }

Example
~~~~~~~

Given this definition:

.. code-block:: lua

    wssdl.packet {
        prefix  : u8();
        var     : bytes();
        suffix  : u8();
    }

And this 3-byte raw packet: ``ababab`` (hexadecimal form)

#. ``prefix`` is parsed, a value of ``0xab`` is found.
#. ``variadic`` is reached, the parser jumps to the last suffix field
#. ``suffix`` is parsed, a value of ``0xab`` is found.

Reverse parsing pitfalls
------------------------

Because suffix fields are parsed bottom-to-top, the resolution rules and the
constraints change slightly to make the reverse parsing possible:

* Null-terminated string types (``utf8z``, ``utf16z``) are prohibited.
  This is because the null character would appear first during the reverse
  parsing, and we would have no way of knowing the size of the field.

* Root packets (i.e. packets used as protocols) are implicitely aligned on an
  8-bit boundary -- mind the alignment constraint when you have unaligned
  suffix fields!

* Fields with a size that depends on the value of another field needs to be
  parsed after the field they depend on is parsed. This means that for suffix
  fields, dependencies needs to appear *after* the field definition.

  For instance, this is invalid:

  .. code-block:: lua

      wssdl.packet {
          prefix    : u8();
          var       : bytes();
          suffix_sz : u8();
          suffix    : bytes(suffix_sz);
      }

  While this is valid:

  .. code-block:: lua

      wssdl.packet {
          prefix    : u8();
          var       : bytes();
          suffix    : bytes(suffix_sz);
          suffix_sz : u8();
      }
