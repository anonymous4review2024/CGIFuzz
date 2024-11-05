# CGIFuzz: A Coverage-guided gray-box fuzzer for Web CGI of IoT devices

This is the prototype code for the paper: 'CGIFuzz: Enabling Gray-Box Fuzzing for Web CGI of IoT
Devices'. It is a fuzzing tool built upon the [GDBFuzz](https://github.com/boschresearch/gdbfuzz) framework.
Please cite the above paper when reporting, reproducing or extending the results.

# Getting Started 

## Install local
__CGIFuzz__ has been tested on Ubuntu 22.04 LTS.
Prerequisites are java and python3. First, create a new virtual environment and install all dependencies.
~~~
virtualenv .venv
source .venv/bin/activate
make
chmod a+x ./src/CGIFuzz/main.py
~~~

## Usage




