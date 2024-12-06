CC = /usr/bin/gcc
LDFLAGS = -lcrypto
LIB=libnewhope512.a

SOURCES = kem.c cpapke.c fips202.c ntt.c poly.c  reduce.c rng.c  verify.c correct_test.c
HEADERS = api.h cpapke.h fips202.h ntt.h params.h poly.h reduce.h verify.h rng.h 
OBJECTS = kem.o cpapke.o fips202.o ntt.o poly.o reduce.o verify.o rng.o 

all: $(LIB)

test: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC)  -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)
	
.PHONY: clean

clean:
	-rm test
