### Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
### All rights reserved.
### 
### Redistribution and use in source and binary forms, with or without
### modification, are permitted provided that the following conditions are met:
### 
###     * Redistributions of source code must retain the above copyright
###       notice, this list of conditions and the following disclaimer.
### 
###     * Redistributions in binary form must reproduce the above copyright
###       notice, this list of conditions and the following disclaimer in the
###       documentation and/or other materials provided with the distribution.
### 
###     * Neither the name of Selective Intellect LLC nor the
###       names of its contributors may be used to endorse or promote products
###       derived from this software without specific prior written permission.
### 
### THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
### ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
### WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
### DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
### DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
### (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
### LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
### ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
### (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
### SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
### 
##################################################################
### COPYRIGHT: 2011-2012 Selective Intellect LLC. All Rights Reserved
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
### SOFTWARE: Wisecracker 
##################################################################
CMAKE=$(shell which cmake)
CTEST=$(shell which ctest)
PREFIX?=/usr/local
ARCH=$(shell uname -m)
OPENCL_ROOT?=/usr
CC=$(shell which gcc)
CXX=$(shell which g++)

RELEASE=
ifeq ($(RELEASE),1)
BUILD_TYPE=MinSizeRel
else
BUILD_TYPE=Debug
endif
BUILD_DIR=${BUILD_TYPE}_$(ARCH)
CMAKEBUILDVAR=-DARCH=$(ARCH) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(PREFIX)

default: all
.PHONY: default

all: buildwise
.PHONY: all

rebuild: clean buildwise
.PHONY: rebuild

release:
	$(MAKE) RELEASE=1
.PHONY: release

debug:
	$(MAKE) RELEASE=0
.PHONY: debug

distclean: cmakeclean
.PHONY: distclean

clean: cleanwise
.PHONY: clean

test: testwise
.PHONY: test

install:
	$(MAKE) installwise RELEASE=1
.PHONY: install

buildwise:
	@mkdir -p $(BUILD_DIR); \
	cd $(BUILD_DIR); \
	export CC=$(CC); \
	export CXX=$(CXX); \
	$(CMAKE) $(CMAKEBUILDVAR) .. ; \
	$(MAKE); \
	echo "$(BUILD_TYPE) Build complete"
.PHONY: wise

cmakeclean: clean
	@if test -d $(BUILD_DIR); then \
		cd $(BUILD_DIR); \
		rm -rf CMakeCache.txt; \
		echo "$(BUILD_TYPE) cmake cleaning complete"; \
	else \
		echo "Nothing to clean for $(BUILD_TYPE)"; \
	fi
.PHONY: cmakeclean

cleanwise:
	@if test -d $(BUILD_DIR); then \
		cd $(BUILD_DIR); \
		$(MAKE) clean; \
		echo "$(BUILD_TYPE) cleaning complete"; \
	else \
		echo "Nothing to clean for $(BUILD_TYPE)"; \
	fi
.PHONY: cleanwise

testwise: buildwise
	@if test -d $(BUILD_DIR); then \
		cd $(BUILD_DIR); \
		$(CTEST); \
	fi
.PHONY: testwise

installwise: buildwise
	@if test -d $(BUILD_DIR); then \
		cd $(BUILD_DIR); \
		$(MAKE) install; \
		echo "$(BUILD_TYPE) installation complete"; \
	else \
		echo "Nothing to install for $(BUILD_TYPE)"; \
	fi
.PHONY: installwise
