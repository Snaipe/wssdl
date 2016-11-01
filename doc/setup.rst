Setup
=====

Prerequisites
-------------

The library needs a recent version of Wireshark and lua 5.1+.

Although the library is expected to work on older versions of Wireshark,
it has only been tested on 2.2.0 and above.

Installing the library
----------------------

From a release
~~~~~~~~~~~~~~

Grab ``wssdl.lua`` from the latest `release <https://github.com/diacritic/wssdl/releases/latest>`_,
and put it in one of Wireshark's plugin paths.

.. note::

    Usually, Wireshark loads plugins from ``~/.config/wireshark/plugins`` and
    ``/usr/lib/wireshark/plugins/<version>``. You can check what directories
    Wireshark checks by going into Help -> About -> Folders.

From source
~~~~~~~~~~~

Building from source requires as an additional prerequisite luarocks and the
luafilesystem module to be installed.

To boostrap the library in one coalesced file, and install it to
``~/.config/wireshark/plugins``, run from the project directory:

.. code-block:: bash

    $ make install

If you prefer to install it in another location, set the variable ``WS_PLUGIN_DIR``.
For instance, to install wssdl in the system plugin path for Wireshark 2.2.0:

.. code-block:: bash

    $ sudo make WS_PLUGIN_DIR=/usr/lib/wireshark/plugins/2.2.0 install
