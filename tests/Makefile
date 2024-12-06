CFLAGS_128 = -Wall -Werror -std=c99  -L../lib -lcake_128  -I ../newhope512cca -I ../include  -lcrypto -lgmp
CFLAGS_256 = -Wall -Werror -std=c99  -L../lib -lcake_256  -I ../newhope1024cca -I ../include -lcrypto -lgmp

all: 128 256

128: test_asymmetric_cake.c
	$(CC) -o test_asymmetric_cake_128 test_asymmetric_cake.c $(CFLAGS_128)


256: test_asymmetric_cake.c
	$(CC) -o test_asymmetric_cake_256 test_asymmetric_cake.c $(CFLAGS_256)

clean:
	$(RM) test_asymmetric_cake_128
	$(RM) test_asymmetric_cake_256

