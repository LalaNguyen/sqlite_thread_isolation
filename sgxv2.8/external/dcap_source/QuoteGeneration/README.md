Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Generation Library Quick Start Guide
================================================

For Windows* OS
----------------- 
## Prerequisites
- Ensure that you have the following required operating systems:
   * Windows* Server 2016 (Long-Term Servicing Channel)
   * Windows* Server 2019 (Long-Term Servicing Channel)
- Ensure that you have the following required hardware:
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*
- Configure the system with the **SGX hardware enabled** option.
- Ensure that you have installed Microsoft Visual C++ Compiler* version 14.14 or higher provided by Microsoft Visual Studio* 2017 version 15.7
- Ensure that you have installed Windows Driver Kit for Win 10, version 10.0.17763.
- Ensure that you have installed latest Intel(R) SGX SDK Installer which could be downloaded from the [Intel(R) SGX SDK](https://software.intel.com/en-us/sgx-sdk/download)
- Use the script to download prebuilt binaries to prebuilt folder:
```
    download_prebuilt.bat
```

## How to build
- In the top directory, open the Microsoft Visual Studio* solution `SGX_DCAP.sln` and run a build.
- The Intel(R) SGX DCAP NuGet* package generation depends on a standalone tool `nuget.exe`. To build the Intel(R) SGX DCAP NuGet* package:
   1.  Download the standalone tool `nuget.exe` from [nuget.org/downloads](https://nuget.org/downloads) and put it to `installer\win\` folder or add the folder where you placed `nuget.exe` to your PATH environment variable. 
   2.  Go to `installer\win\` folder and run the following command from the Command Prompt:
```
    DCAP_Components.bat
```
   The target NuGet* package `DCAP_Components.<version>.nupkg` will be generated in the same folder.
- To build the Intel(R) SGX DCAP INF installers, go to `installer\win\Dcap\` folder and run the following commands from the Visual Studio Command Prompt:
```
    dcap_copy_file.bat
    dcap_generate.bat <version>
```
  The target INF installers `sgx_dcap.inf` and `sgx_dcap_dev.inf` will be generated in the same folder. 
**NOTE**:`sgx_dcap_dev.inf` is for Windows* Server 2016 LTSC and `sgx_dcap.inf` is for Windows* Server 2019 LTSC.

## How to install
   Refer to the *"Installation Instructions"* section in the [Intel(R) Software Guard Extensions: Data Center Attestation Primitives Installation Guide For Windows* OS](https://download.01.org/intel-sgx/sgx-dcap/1.4/windows/docs/Intel_SGX_DCAP_Windows_SW_Installation_Guide.pdf) to install the right packages on your platform.


For Linux* OS
-----------------
## Prerequisites
- Ensure that you have the following required operating systems:
  * Ubuntu* 16.04 LTS Desktop 64bits - minimal kernel 4.10
  * Ubuntu* 16.04 LTS Server 64bits - minimal kernel 4.10
  * Ubuntu* 18.04 LTS Desktop 64bits
  * Ubuntu* 18.04 LTS Server 64bits
- Ensure that you have the following required hardware:
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*
- Configure the system with the **SGX hardware enabled** option.
- Use the following command(s) to install the required tools to build the Intel(R) SGX software:
```
  $ sudo apt-get install build-essential wget python debhelper zip
```
- Install latest prebuilt Intel(R) SGX SDK Installer from [01.org](https://01.org/intel-software-guard-extensions/downloads)
```
  $ ./sgx_linux_x64_sdk_${version}.bin
```
  In case you want to build Intel(R) SGX Installer, follow the instructions to build a compatible SDK and PSW on master branch of GitHub [Intel SGX for Linux*](https://github.com/intel/linux-sgx).
- Use the script ``download_prebuilt.sh`` inside source code package to download prebuilt binaries to prebuilt folder
  You may need set an https proxy for the `wget` tool used by the script (such as ``export https_proxy=http://test-proxy:test-port``)
```
  $ ./download_prebuilt.sh
```

## Build and Install Intel(R) SGX Driver
A `README.md` is provided in the Intel(R) SGX driver package for Intel(R) SGX DCAP. Please follow the instructions in the `README.md` to build and install Intel(R) SGX driver.
- The enclave user needs to be added to the group of "sgx_prv" if customers want to use their own provision enclave:
```
  $ sudo usermod -aG sgx_prv user
```

## Build the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library Package
- To set the environment variables, enter the following command:
```
  $ source ${SGX_PACKAGES_PATH}/sgxsdk/environment
```
- To build the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library package, enter the following command:
```
   $ make
``` 
The target package named ``linux_dcap_interface.zip`` will be generated.
- To clean the files generated by previous `make` command, enter the following command:
```
  $ make clean
```
- To rebuild the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library package, enter the following command:
```
  $ make rebuild
```
- To build debug libraries, enter the following command:
```
  $ make DEBUG=1
```
- To build the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library installers, enter the following command:
```
  $ make deb_pkg
```
  You can find the generated installers located under `linux/installer/deb/`.
  **Note**: On Ubuntu 18.04, the above command also generates another debug symbol package with extension name of `.ddeb` for debug purpose. On Ubuntu 16.04, if you want to keep debug symbols, you need to export an environment variable to ensure the debug symbols not stripped:
   ```
   $ export DEB_BUILD_OPTIONS="nostrip"
   ```
  **Note**: The above command builds the installers with default configuration firstly and then generates the target installers. To build the installers without optimization and with full debug information kept in the libraries, enter the following command:
  ```
  $ make deb_pkg DEBUG=1
  ```

## Install the Intel(R) SGX DCAP Quote Generation Library Package
- Install prebuilt Intel(R) SGX common loader and other prerequisites from [01.org](https://01.org/intel-software-guard-extensions/downloads)
```
  & sudo dpkg -i --force-overwrite libsgx-ae-pce_*.deb libsgx-ae-qe3_*.deb libsgx-ae-qve_*.deb libsgx-enclave-common_*.deb libsgx-urts_*.deb
```
**NOTE**: Because we've split libsgx-enclave-common into multiple packages since 2.8 release, you need to add `--force-overwrite` to overwrite existing files if you've installed libsgx-enclave-common< 2.8. If you're doing a fresh install, you can omit this option.

- For production systems, package should be installed by the following command:
```
  $ sudo dpkg -i libsgx-dcap-ql_*.deb
```
- For development systems, another two packages should be installed by the following commands:
```
  $ sudo dpkg -i libsgx-dcap-ql-dev_*.deb
  $ sudo dpkg -i libsgx-dcap-ql-dbgsym_*.deb
```

## Install the Intel(R) SGX Default Quote Provider Library Package
- For production systems, package should be installed by the following commands:
```
  $ sudo dpkg -i libsgx-dcap-default-qpl_*.deb
  $ sudo dpkg -i libsgx-dcap-pccs_*.deb
```
  Please refer to /opt/intel/libsgx-dcap-pccs/README.md for more details about the installation of libsgx-dcap-pccs.
- For development systems, another two packages should be installed by the following commands:
```
  $ sudo dpkg -i libsgx-dcap-default-qpl-dev_*.deb
  $ sudo dpkg -i libsgx-dcap-default-qpl-dbgsym_*.deb
```
