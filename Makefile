MKDIR=mkdir -p

LIB_CAKE_128 = libcake_128.a
LIB_CAKE_256 = libcake_256.a

HEADERS = src/feistel.h src/commons.h src/cake.h src/encode.h src/ciphertext.h src/publickey.h src/crypto_tools.h src/omega_transform.h
OBJECTS_128 = bin/128/feistel.o bin/128/commons.o bin/128/cake.o bin/128/encode.o bin/128/ciphertext.o bin/128/publickey.o bin/128/crypto_tools.o bin/128/omega_transform.o
OBJECTS_256 = bin/256/feistel.o bin/256/commons.o bin/256/cake.o bin/256/encode.o bin/256/ciphertext.o bin/256/publickey.o bin/256/crypto_tools.o bin/256/omega_transform.o

LIB_NEWHOPE_512=newhope512cca/libnewhope512.a
LIB_NEWHOPE_1024=newhope1024cca/libnewhope1024.a
CFLAGS = -Wall -Werror -std=c99 -O3 

all: 128 256

128: $(LIB_CAKE_128)
	$(MAKE) -C tests 128 -j 4
#	$(MAKE) -C benchmark 128 -j 4

$(LIB_CAKE_128): $(OBJECTS_128)  $(LIB_NEWHOPE_512)
	$(MKDIR) newhope-dump && cd newhope-dump && ar -x ../$(LIB_NEWHOPE_512) && cd ..
	$(MKDIR)  lib
	$(AR) -r lib/$@ $(OBJECTS_128)  newhope-dump/*.o
	$(RM) -r newhope-dump

$(LIB_NEWHOPE_512):
	$(MAKE) -C newhope512cca -j 4

bin/128/%.o: src/%.c $(HEADERS)
	$(MKDIR) $(@D)
	$(CC) $(CFLAGS) -I newhope512cca -c -o $@ $<

256: $(LIB_CAKE_256)
	$(MAKE) -C tests 256 -j 4
#	$(MAKE) -C benchmark 128 -j 4

$(LIB_CAKE_256): $(OBJECTS_256)  $(LIB_NEWHOPE_1024)
	$(MKDIR) newhope-dump && cd newhope-dump && ar -x ../$(LIB_NEWHOPE_1024) && cd ..
	$(MKDIR) lib
	$(AR) -r lib/$@ $(OBJECTS_256)  newhope-dump/*.o
	$(RM) -r newhope-dump

$(LIB_NEWHOPE_1024):
	$(MAKE) -C newhope1024cca -j 4
	
bin/256/%.o: src/%.c $(HEADERS)
	$(MKDIR) $(@D)
	$(CC) $(CFLAGS) -I newhope1024cca -c -o $@ $<

clean:
	$(RM) -r bin
	$(RM) -r lib
	$(MAKE) -C newhope512cca clean
	$(MAKE) -C newhope1024cca clean
	$(MAKE) -C  tests clean
	$(MAKE) -C  benchmark clean