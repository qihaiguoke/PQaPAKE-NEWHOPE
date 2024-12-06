CC = /usr/bin/gcc
LDFLAGS = -lcrypto
LIB=libnewhope1024.a

SOURCES = kem.c cpapke.c fips202.c ntt.c poly.c precomp.c reduce.c rng.c verify.c PQCgenKAT_kem.c
HEADERS = api.h cpapke.h fips202.h ntt.h params.h poly.h reduce.h rng.h verify.h
OBJECTS = kem.o cpapke.o fips202.o ntt.o poly.o precomp.o reduce.o rng.o verify.o 

all: $(LIB)

PQCgenKAT_kem: $(SOURCES) $(HEADERS)
	$(CC) $(SOURCES) -o $@ $(LDFLAGS)


%.o: %.c $(HEADERS)
	$(CC)  -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

.PHONY: clean

clean:
	$(RM) PQCgenKAT_kem
	$(RM) $(OBJECTS)
	$(RM) $(LIB)

