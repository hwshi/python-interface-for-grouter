# Python Interface For gRouter

Installation
gRouter works with GINI platform. The documentation assumes that GINI is already installed in your PC.
details for installing GINI (http://cgi.cs.mcgill.ca/~anrl/gini/documentation.html)

1. Update gRouter with the gRouter in this responsitory.

2. Download and Install SWIG(http://www.swig.org/Doc3.0/SWIGDocumentation.html#Preface_installation)
Download SWIG at http://www.swig.org/download.html
sample for install SWIG on UNIX:
```
    $ ./configure
    $ make
    $ make install
```
3. Download and Install Scapy(http://www.secdev.org/projects/scapy/doc/installation.html)
```
    $ cd /tmp
    $ wget scapy.net
    $ unzip scapy-latest.zip
    $ cd scapy-2.*
    $ sudo python setup.py install
```

4. Use the MAKEFILE in the /src direcotry to build the gRouter
5. The module built using Python is dynamically installed into gRouter at run-time.
After GINI is running. Copy all the needed files into the .gini/data/Router#.
```
    _GINIC.so
    GINIC.py
    ginilib.py
    udp.py
```
Open the CLI of gRouter using command "addmod" to install the module.
```
    addmod udp python
```
if the config function is implemented correctly. A config table will be shown and states that the module is installed.
