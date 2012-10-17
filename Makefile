### Wisecracker: A cryptanalysis framework
### Copyright (c) 2011-2012, Vikas Naresh Kumar, Selective Intellect LLC
###    
###	This program is free software: you can redistribute it and/or modify
### it under the terms of the GNU General Public License as published by
### the Free Software Foundation, either version 3 of the License, or
### any later version.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.
###
### You should have received a copy of the GNU General Public License
### along with this program.  If not, see <http://www.gnu.org/licenses/>.
#########################################################################
### COPYRIGHT: 2011-2012 Selective Intellect LLC. All Rights Reserved
### AUTHOR: Vikas Kumar
### DATE: 21st Dec 2011
### SOFTWARE: Wisecracker 
#########################################################################
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
BUILD_DIR=Release_$(ARCH)
else
BUILD_TYPE=Debug
BUILD_DIR=Debug_$(ARCH)
endif
CMAKEBUILDVAR=-DARCH=$(ARCH) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(PREFIX)

default: all
.PHONY: default

all: buildwise
.PHONY: all

rebuild: distclean buildwise
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
.PHONY: buildwise

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
