
CC = gcc
CXX = @CXX@
AS = gcc
LD = gcc
CPP = gcc
CPPFLAGS =  -I/usr/local/include -DCL_SILENCE_DEPRECATION
CFLAGS = -c -DAC_BUILT -mavx512bw -mavx512vl -mavx512dq  -maes -mpclmul -DJOHN_AVX512BW -g -O2 -I/usr/local/include -DARCH_LITTLE_ENDIAN=1 -DPREFER_FLOCK  -Wall -std=gnu99 -Wno-stringop-truncation -Wno-format-overflow -Wno-format-truncation -fno-omit-frame-pointer -Wno-deprecated-declarations -Wformat-extra-args -Wunused-but-set-variable -Wdate-time -D_POSIX_SOURCE -D_GNU_SOURCE -D_XOPEN_SOURCE=600  -fopenmp    -I/usr/local/include -DCL_SILENCE_DEPRECATION -Wno-unused-function
ASFLAGS =  -DARCH_LITTLE_ENDIAN=1 -c 
LDFLAGS =  -L/usr/local/lib -L/usr/lib64 -L/lib64
AR = /usr/bin/ar
FIND = /usr/bin/find
RM = /bin/rm -f

IN = poly1305-donna.o

all: poly1305-donna.a
default: poly1305-donna.a

poly1305-donna.o: poly1305-donna.c
	$(CC) -DHAVE_CONFIG_H $(CFLAGS) $(CPPFLAGS) -c poly1305-donna.c -o poly1305-donna.o

.PHONY: subdirs $(SUBDIRS)

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ all

poly1305-donna.a: $(SUBDIRS) poly1305-donna.o
	$(AR) -rs $@ $(IN)

clean:
	$(FIND) . -name \*.a -exec $(RM) {} \;
	$(FIND) . -name \*.o -exec $(RM) {} \;

distclean: clean
	$(RM) Makefile
