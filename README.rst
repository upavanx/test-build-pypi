==================================================================
Edge Software Builder: Command Line Interface for Package Building
==================================================================

This is a client library for installing modules in a package.
It provides a command-line tool (edgesoftware).

Installation Steps
------------------
edgesoftware CLI can be installed from sources. This is a preferred and quicker way for Developers.

************
For Linux:
************


One time setup only:
^^^^^^^^^^^^^^^^^^^^

    $ *sudo apt-get update && sudo apt install python3-pip -y* (On Ubuntu/Debian based systems)

    $ *sudo yum update -y && sudo yum install gcc python3-devel python3-pip -y* (On CentOS/RHEL based systems)

    $ *pip3 install --upgrade pip*
    
    $ *pip3 install -r requirements.txt*

**Generate the Binary:**
 
    $ *sudo python3 setup.py install*

************
For Windows:
************

One time setup only
^^^^^^^^^^^^^^^^^^^

    $ *pip install --upgrade pip*

    $ *pip install -r requirements.txt*

**Generate the Binary:**
 
    $ *python setup.py install*


Generate Python Executable
--------------------------

**Preferred way for Validation and E2E testing::**

To generate ``edgesoftware`` executable for **Linux** based systems::

    $ git clone --single-branch https://gitlab.devtools.intel.com/software_recipe/software_recipe_components/common
    $ cd common
    $ python3 build_common.py
    $ cd -
    $ sudo python3 setup.py install && sudo rm -rf build/ dist/ edgesoftware.egg-info
    $ pyinstaller edgesoftware.spec

The executable will be available at ``dist/edgesoftware``.

Usage
-----

Use the ``edgesoftware`` command to download, install, list, log, pull, update and upgrade
packages/modules in a recipe. For help run::

    $ edgesoftware --help

For example::

    $ edgesoftware install

Running Tests
-------------

To run tests::

    $ python3 test/functional/test.py
