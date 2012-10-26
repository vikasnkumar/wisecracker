#!/bin/sh
SUDO=`which sudo`
YUM=`which yum`
if test -z ${YUM}; then
	echo "YUM package manager is not installed."
	exit 1
fi
if test -z ${SUDO}; then
	echo "SUDO is not installed"
	exit 1
fi
${SUDO} ${YUM} -y install cmake git gcc gcc-c++ gdb make glibc-devel || exit 1
${SUDO} ${YUM} -y install openssl-devel libstdc++-devel || exit 1
${SUDO} ${YUM} -y install nvidia nvidia-gpu-sdk-bin nvidia-gpu-sdk cudatoolkit || exit 1
${SUDO} ${YUM} -y install openmpi-devel openmpi || exit 1

export OPENCL_ROOT=/opt/nvidia/gpu_sdk/OpenCL
export MPIPATH=/usr/lib64/openmpi/bin
export PATH=${PATH}:${MPIPATH}
if test -d ${OPENCL_ROOT} && test -d ${MPIPATH} ; then
	echo "===================================================================================="
	echo "Please add the following line to your .bashrc or .profile"
	echo "export OPENCL_ROOT=${OPENCL_ROOT}"
	echo "export PATH=\${PATH}:${MPIPATH}"
	echo "You might need to reboot your VM as well to allow for the NVIDIA module to work"
	echo "===================================================================================="
else
	echo "===================================================================================="
	echo "Something went wrong. ${OPENCL_ROOT} or ${MPIPATH} was not created by the yum install"
	echo "===================================================================================="
	exit 1
fi
