==================================================================
Edge Software Builder: Command Line Interface for Package Building
==================================================================

This is a client library for installing modules in a package.
It provides a command-line tool (edgesoftware).

Installation
------------

To install the ``edgesoftware`` command::

    $ sudo apt-get update && sudo apt install python3-pip -y && pip3 install setuptools
    
    $ sudo python3 setup.py install

Usage
-----

Use the ``edgesoftware`` command to install, list, update and upgrade
packages in a recipe. For help run::

    $ edgesoftware --help

For example::

    $ edgesoftware install

Running Tests
-------------

To run tests::

    $ python3 test/functional/test.py

Generate Python Executable
--------------------------

To generate ``edgesoftware`` executable::

    $ pip3 install pyinstaller
    $ pyinstaller edgesoftware.spec

The executable will be available at ``dist/edgesoftware``.
