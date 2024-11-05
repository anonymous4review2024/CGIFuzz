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
1. WebCrawler is our prototype code based on an LLM (Large Language Model) that captures data packets from different devices. It allows for device-specific modifications and runs to capture packets unique to each device. In the same directory, we have included data packets collected from several experimental programs.

2. Upload the necessary files from the experiment directory to the testing device and execute them.

3. Run the CGIFuzz program. Configuration files for different inputs can be found in the experiment directory. By default, the packets collected in step one are used as seeds for fuzz testing.
