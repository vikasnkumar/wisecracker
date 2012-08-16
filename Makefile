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
