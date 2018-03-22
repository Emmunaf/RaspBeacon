# BeaconPi
BeaconPi is a python project.

  - ...
# Dipendencies 

  - Python > 3.4
  - Bluez library 
  - Crypto module

You should also have the following requirements:
  - Raspberry
  - ..

### Installation

Dillinger requires the BlueZ library to run, installing it on a raspberry could be very annoying. You can choose to way:
##### First one
Download and compile last version of boost available.
Download the [Gattlib library] library then you need to modify the setup.py script in order to work with python != 3.4.
In order to do that you can execute the following commands and replace "boost_python-py35" with "boost_python-py<your_version>", where <your_version> = <35|36|..>
Compile libboost library with PYTHON_VER=3 flag on your raspberry then:
```sh
$ sudo apt-get install libbluetooth-dev libreadline-dev libgtk2.0-dev
$ wget https://pypi.python.org/packages/be/2f/5b1aecec551b42b59d8b399ad444b5672972efb590ca83d784dbe616a3e1/gattlib-0.20150805.tar.gz
$ tar -xvzf gattlib-0.20150805.tar.gz
$ cd  gattlib-*
$ sed -ie 's/boost_python-py34/boost_python-py35/' setup.py
$ python3 setup.py install 
```

##### Second one
Flash a dd image with bluez already set up.
Link: 


### Todos

 - Write MORE Tests
 - Add Night Mode

License
----

[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job. There is no need to format nicely because it shouldn't be seen. Thanks SO - http://stackoverflow.com/questions/4823468/store-comments-in-markdown-syntax)


   [gattlib library]: <https://github.com/labapart/gattlib>
   [git-repo-url]: <https://github.com/labapart/gattlib.git>
   
