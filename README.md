Wisecracker
===========

Large scale brute force cryptanalysis needs a tremendous amount of computational
power that government agencies like the NSA and companies like Google have.

An average security researcher might want to have such capabilities as well but
they do not have the tools or the computational resources. Moreover, they might
not be skilled in writing software that takes advantage of the computational
resources provided by commercial-off-the-shelf systems with CUDA and OpenCL
capable GPUs and computational clusters provided by Amazon EC2 and Microsoft 
Azure.

With Wisecracker we bridge this gap by providing an open source framework for
security researchers to write their own cryptanalysis tools that can distribute
brute force cryptanalysis work across multiple systems with multiple multi-core
processors and GPUs. Security researchers can also use the sample tools
provided as part of Wisecracker out-of-the-box.

The differentiating aspect of Wisecracker is that it uses OpenCL and MPI
together to distribute the work across multiple systems each having
multiple CPUs and/or GPUs. We support the OpenCL libraries provided by
Intel, AMD and NVIDIA, and support multiple operating systems such as Linux,
Microsoft Windows and Mac OSX.

Wisecracker is licensed under the GNU General Public License version 3 and is
free for anyone to use and enhance. 

More information on the design details can be found at
http://selectiveintellect.com/wisecracker.html .

The developers at Selective Intellect LLC would like to hear from you about
Wisecracker if you like it or need a different license or need technical
support. You can contact them at <wisecracker@selectiveintellect.com>.

0. How to build the software
=============================

Please read the INSTALL file to perform the build.
The current system is only supported on Linux, Mac OSX and Windows. However the
software will work only in 64-bit mode and hence you will need a 64-bit capable
operating system to compile and run it.

1. License
===========

The software license is GNU General Public License version 3. You can find the
license in the COPYRIGHT file of the source code.

2. API Documentation
====================

The API documentation can be found in the docs/ directory or on the website
http://selectiveintellect.com/wisecracker.html

3. Current Stable Version
==========================

The current stable version is 1.0.

4. Technical Details and Usage
================================

This information can be downloaded from
http://selectiveintellect.com/wisecracker_whitepaper.pdf or can be taken from
the docs/ directory of the source code.


5. Final Comments
================

We understand that the software might be deficient in some aspects, but software
evolves and so will Wisecracker.

Thanks for trying it out,
The development team at Selective Intellect LLC.
