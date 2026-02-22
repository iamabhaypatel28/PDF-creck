
CC = gcc
AS = gcc
LD = gcc
CPP = gcc
CFLAGS = -c -DAC_BUILT -mavx512bw -mavx512vl -mavx512dq  -maes -mpclmul -DJOHN_AVX512BW -g -O2 -I/usr/local/include -DARCH_LITTLE_ENDIAN=1 -DPREFER_FLOCK  -Wall -std=gnu99 -Wno-stringop-truncation -Wno-format-overflow -Wno-format-truncation -fno-omit-frame-pointer -Wno-deprecated-declarations -Wformat-extra-args -Wunused-but-set-variable -Wdate-time -D_POSIX_SOURCE -D_GNU_SOURCE -D_XOPEN_SOURCE=600  -fopenmp    -I/usr/local/include -DCL_SILENCE_DEPRECATION
ASFLAGS =  -DARCH_LITTLE_ENDIAN=1 -c 
LDFLAGS =  -L/usr/local/lib -L/usr/lib64 -L/lib64
AR = /usr/bin/ar
RM = /bin/rm -f
AESIN = aesce.o aesni.o aes.o

default: aes.a
all: aes.a

aes.o:	aes.c common.h build_info.h mbedtls_config.h alignment.h aes.h private_access.h platform_util.h platform.h error.h aesni.h aesce.h ctr.h
	$(CC) $(CFLAGS) -c aes.c -o aes.o

aesce.o:	aesce.c common.h build_info.h mbedtls_config.h alignment.h aesce.h aes.h private_access.h platform_util.h
	$(CC) $(CFLAGS) -c aesce.c -o aesce.o

aesni.o:	aesni.c common.h build_info.h mbedtls_config.h alignment.h aesni.h aes.h private_access.h platform_util.h
	$(CC) $(CFLAGS) -c aesni.c -o aesni.o

aes.a: $(AESIN)
	$(AR) -rs aes.a $(AESIN)

clean:
	$(RM) *.a *.o

distclean: clean
	$(RM) Makefile
