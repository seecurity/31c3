#
#	Makefile for MatrixSSL Open Source product package
#   'make' builds optimized (-Os default).
#   'make debug' builds debug mode.
#
#	Copyright (c) INSIDE Secure Corporation. 2013 All Rights Reserved.
#

#
#	Set to determine which core/OS directory is compiled
#
OSDEP	= POSIX

CC      = gcc
STRIP   = strip
AR      = ar
O       = .o
SO      = .so
A       = .a
E       =

SSL_DYN= libmatrixssl$(SO)
SSL_STATIC = libmatrixssl$(A)

CORE_OBJECTS = \
	./core/corelib$(O) \
	./core/$(OSDEP)/osdep$(O)

CRYPTO_OBJECTS = \
	./crypto/keyformat/asn1$(O) \
	./crypto/keyformat/base64$(O) \
	./crypto/keyformat/x509$(O) \
	./crypto/digest/hmac$(O) \
	./crypto/digest/md5$(O) \
	./crypto/digest/sha1$(O) \
	./crypto/math/pstm$(O) \
	./crypto/math/pstm_mul_comba$(O) \
	./crypto/math/pstm_sqr_comba$(O) \
	./crypto/math/pstm_montgomery_reduce$(O) \
	./crypto/pubkey/pubkey$(O) \
	./crypto/pubkey/pkcs$(O) \
	./crypto/pubkey/rsa$(O) \
	./crypto/prng/prng$(O) \
	./crypto/prng/yarrow$(O) \
	./crypto/symmetric/aes$(O) \
	./crypto/symmetric/arc4$(O) \
	./crypto/symmetric/rc2$(O) \
	./crypto/symmetric/des3$(O)

SSL_OBJECTS = \
	./matrixssl/cipherSuite$(O) \
	./matrixssl/hsHash$(O) \
	./matrixssl/matrixssl$(O) \
	./matrixssl/matrixsslApi$(O) \
	./matrixssl/sslDecode$(O) \
	./matrixssl/sslEncode$(O) \
	./matrixssl/prf$(O) \
	./matrixssl/tls$(O) \
	./matrixssl/sslv3$(O)

#
# This is set by the debug target below
#
ifdef PS_DEBUG
  DFLAGS  = -g -Wall -Winline -Wdisabled-optimization -DDEBUG
  STRIP   = test
else
  DFLAGS  = -Os
endif

ifdef PS_PROFILE
  DFLAGS = -g -pg
  STRIP = test
endif

gold:
	@$(MAKE) compile

debug:
	@$(MAKE) compile "PS_DEBUG = 1"

profile:
	@$(MAKE) compile "PS_PROFILE = 1"

default: gold

#
# Compile options
#
SHARED	= -shared
CFLAGS  = $(DFLAGS) -D$(OSDEP) -I./ -I../ -fomit-frame-pointer
LDFLAGS = -lc

#
# Platform specific optimizations
#
ifeq ($(shell uname),Darwin)
  #
  # Override variables for compilation on Mac OS X (Darwin)
  # Notice we do not build a dynamic library on Mac. There are issues with
  #   building dynamic and compiling with assembly optimizations.
  #
  STRIP = test
  SO = .dylib
  SHARED = -dynamiclib
  CFLAGS += -isystem -I/usr/include
  NOPIC = -mdynamic-no-pic
  #
  # Use the compiler default to figure out 32 or 64 bit mode
  #
  CCARCH = $(shell $(CC) -v 2>&1)
  ifneq (,$(findstring x86_64,$(CCARCH)))
    CFLAGS += -DPSTM_64BIT -DPSTM_X86_64
  else
    LDFLAGS += -read_only_relocs suppress
    ifndef PS_DEBUG
      CFLAGS += -DPSTM_X86
    endif
  endif
else
  #
  # Linux shows the architecture in uname
  #
  ifeq ($(shell uname -m),x86_64)
    CFLAGS  += -fPIC -DPSTM_64BIT -DPSTM_X86_64
  else
    CFLAGS  += -DPSTM_X86
  endif
endif

#
#	Override variables for cross compilation Linux (example only)
#	These should be replaced by the paths to your cross compiler
#
ifdef UCLINUX
  CC      = arm-elf-linux-gcc
  STRIP   = arm-elf-linux-strip
  AR      = arm-elf-linux-ar
endif

all: compile

compile: $(SSL_STATIC) $(SSL_DYN)

$(CORE_OBJECTS): core/*.h core/*.c core/*/*.c

$(CRYPTO_OBJECTS): DFLAGS += $(NOPIC)
$(CRYPTO_OBJECTS): $(CORE_OBJECTS) crypto/*.h crypto/*/*.h crypto/*/*.c

$(SSL_OBJECTS): $(CORE_OBJECTS) $(CRYPTO_OBJECTS) matrixssl/*.c matrixssl/*.h

#
# Build the dynamic SSL library
#
$(SSL_DYN): $(CORE_OBJECTS) $(CRYPTO_OBJECTS) $(SSL_OBJECTS)
	$(CC) $(SHARED) -o $@ $^ $(LDFLAGS)
	$(STRIP) $(SSL_DYN)

#
# Build the static SSL library
# Direct stderr to null so we don't see the 'empty file' warnings
#
$(SSL_STATIC): $(CORE_OBJECTS) $(CRYPTO_OBJECTS) $(SSL_OBJECTS)
	$(AR) -rcuv $@ $^ 2>/dev/null

#
#	Clean up all generated files
#
clean:
	rm -f $(CORE_OBJECTS) $(CRYPTO_OBJECTS) $(SSL_OBJECTS) $(SSL_DYN) $(SSL_STATIC)

