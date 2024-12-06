CFLAGS_128 = -Wall -Werror -std=c99 -L../lib -lcake_128 -I ../newhope512cca -I ../include -lm -lcrypto -lgmp
CFLAGS_256 = -Wall -Werror -std=c99 -L../lib -lcake_256 -I ../newhope1024cca -I ../include -lm -lcrypto -lgmp

all: acake_128 acake_256 idealcipher_128 idealcipher_256

acake_128: alice_bob.c benchmark.c benchmark.h
	$(CC) -o acake_128 alice_bob.c benchmark.c -I../include $(CFLAGS_128)

acake_256: alice_bob.c benchmark.c benchmark.h
	$(CC) -o acake_256 alice_bob.c benchmark.c -I../include $(CFLAGS_256)

idealcipher_128: idealcipher.c benchmark.c benchmark.h
	$(CC) -o idealcipher_128 idealcipher.c benchmark.c -I../newhope1024cca -I../src $(CFLAGS_128)

idealcipher_256: idealcipher.c benchmark.c benchmark.h
	$(CC) -o idealcipher_256 idealcipher.c benchmark.c -I../newhope1024cca -I../src $(CFLAGS_256)

clean:
	$(RM) acake_128
	$(RM) acake_256
	$(RM) idealcipher_128
	$(RM) idealcipher_256
