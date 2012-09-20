Wisecracker
===========

Wisecracker is a collection of simple cryptanalysis tools. The aim is to expand
this software into a larger code base for performing easy cryptanalysis using
distributed computing power such as that provided by OpenCL. It is licensed
under the GPLv3. If you want to license it under another license, please contact
the developers at Selective Intellect LLC at <github@selectiveintellect.com>.

0. How to build the software
=============================

Please read the INSTALL file to perform the build.
The current system is only supported on Linux, Mac OSX and Windows. However the
software will work only in 64-bit mode and hence you will need a 64-bit capable
operating system to compile and run it.

1. WisecrackMD5
================

WisecrackMD5 is a simple program that uses OpenCL to perform parallel MD5
cracking for 8-character passwords. The aim is to be able to take an MD5 sum and
reverse it into the 8 characters that created the sum in the first place.

Let us take the situation where the user ends up finding a database with MD5
sums of all the passwords from a random website. The user decides to crack such
passwords to get access to those accounts, similar to Jack the Ripper software.
Let us assume that the password is of maximum 8-character length.

The user provides an MD5 checksum for which they want to find an 8-character
password that might match the checksum.

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

The user can then massively parallelize by running multiple instances of
wisecrackmd5 with different prefixes of say 1 character each on a large cluster
that supports OpenCL and be able to retrieve passwords much faster.

We understand that the software might be deficient in some aspects, but software
evolves and so will Wisecracker.

Thanks for trying it out,
The development team at Selective Intellect LLC.
