#!/usr/bin/env bash

#remove aesm service
sudo /opt/intel/sgx-aesm-service/cleanup.sh
sudo rm -rf /opt/intel/sgx-aesm-service
sudo dpkg --remove sgx-aesm-service sgx-aesm-service-dbgsym 
sudo /opt/intel/sgxpsw/uninstall.sh
sudo /opt/intel/sgxdriver/uninstall.sh
sudo /opt/intel/sgxsdk/uninstall.sh

#navigate to driver folder
cd /home/lala/Desktop/sgx_thread_isolation/
sudo ./sgx_linux_x64_driver_2.6.0_51c4821.bin
cd sgxv2.8/
#install sdk
sudo make clean
sudo chown -R lala /home/lala/Desktop/sgx_thread_isolation/sgxv2.8/sdk/cpprt/
sudo chown -R lala linux/installer/common/sdk/pkgconfig/x64/
make -j12 sdk_install_pkg DEBUG=1
sudo ./linux/installer/bin/sgx_linux_x64_sdk_2.8.100.3.bin  

#install aesm
make -j12 deb_sgx_aesm_service DEBUG=1
sudo chown -R lala linux/installer/common/psw/
make -j12 psw_install_pkg DEBUG=1
sudo dpkg -i ./linux/installer/deb/sgx-aesm-service/sgx-aesm-service_2.8.100.3-bionic1_amd64.deb ./linux/installer/deb/sgx-aesm-service/sgx-aesm-service-dbgsym_2.8.100.3-bionic1_amd64.ddeb
sudo ./linux/installer/bin/sgx_linux_x64_psw_2.8.100.3.bin

