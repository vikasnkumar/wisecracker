Wisecracker
===========

Wisecracker is a collection of simple cryptanalysis tools. The aim is to expand
this software into a larger code base for performing easy cryptanalysis using
distributed computing power such as that provided by OpenCL.

0. How to build the software
=============================

Please read the INSTALL file to perform the build.
The current system is only supported on Linux. Mac OS X and Windows support
might come later if the software and its users demand it.

1. WisecrackMD5
================

WisecrackMD5 is a simple program that uses OpenCL to perform parallel MD5
cracking for 8-character passwords. The aim is to be able to take an MD5 sum and
reverse it into the 8 characters that created the sum in the first place.

The user provides an MD5 checksum for which
they want to find an 8-character password that might match the checksum.

Obviously, we expect the user to know that the MD5 sum is that of an 8-character
password. 

The search space for characters is currently [A-Za-z0-9_$]. We will add more
characters later and allow for < 8 password matching as well when time permits.

To use wisecrackmd5, the user provides an MD5 sum and also guesses a prefix of
maybe 1 or 2 or more characters as a guess of the starting value and the program
finds the rest of the characters by executing on the GPU in parallel. If you
have a CPU based OpenCL installation it will use the CPU instead of the GPU.

It can take anything from milliseconds to a few hundred seconds depending on the
size of the prefix to guess the correct 8 characters.

To look at the possible commandline options:
$ ./wisecrackmd5  -h

To test the software with an MD5 sum one can try:

$ ./wisecrackmd5 -p abcd -M a3118ebd990c3506ddd1a77be6962faf

This will find the correct string "abcd9_Z$" that gives the MD5 sum
a3118ebd990c3506ddd1a77be6962faf in about 5-6 seconds.

The user can try giving a shorter prefix such as 'abc' or 'ab' or 'a' to try out
how long it takes for a GPU or CPU cluster using OpenCL to reverse the MD5 sum.

We understand that the software might be deficient in some aspects, but software
evolves and so will Wisecracker.

Thanks for trying it out,
The development team at Selective Intellect LLC.
