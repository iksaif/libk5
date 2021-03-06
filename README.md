# libk5

Easy to use Kerberos library. Contains re-implemented tools like
kinit, kdestroy, kvno and klist. Also contains krb5-test to test
your kerberos configuration and ability to request tickets to access
to services.

## Build

Don't forget to set theses variables correctly:
- CMAKE_BUILD_TYPE
- CMAKE_INSTALL_PREFIX

### Windows

Install Kerberos for Windows
Install CMake and add it to your path

If you want to build something that you can distribute without
any issue, don't forget -DCMAKE_BUILD_TYPE=Release !

#### Visual C++:

Open a shell with vc env correctly defined (there is a .bat for that)

    cmake .. -DKRB5_KFW_PATH="c:/Program Files/MIT/Kerberos/"
    make
    make install

#### MinGW 32:

Open a shell with vc env correctly defined (there is a .bat for that)

   cmake .. -DKRB5_KFW_PATH="c:/Program Files/MIT/Kerberos/" -G"MinGW Makefiles"
   make
   make install

### Linux

Install Kerberos dependencies (libkrb5-dev)

    cmake ..
    make
    sudo make install

### Mac-OS X

Useful variables:

CMAKE_OSX_ARCHITECTURES=
CMAKE_OSX_SYSROOT=
CMAKE_OSX_DEPLOYMENT_TARGET=

Example:

    cmake .. -DCMAKE_OSX_ARCHITECTURES=i386 -DCMAKE_OSX_SYSROOT=/Developer/SDKs/MacOSX10.5.sdk -DCMAKE_OSX_DEPLOYMENT_TARGET=10.5
    make
    sudo make install
