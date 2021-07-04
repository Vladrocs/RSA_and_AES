FLAGS = -Wall
INCLUDE_PATH = -I../include
LIBS_PATH = -L ../lib
LIBS = -lmbedtls -lmbedx509 -lmbedcrypto

all: crypt_and_hash.exe
	
%.o: %.c 
	gcc -c $(INCLUDE_PATH) $< -o $@
	
%.exe: %.o
	gcc $(THIRDPARTY_INCLUDES) $< $(LIBS_PATH) $(LIBS) $(MBEDTLS_TEST_OBJS) -o $@

code:
	./crypt_and_hash 0 date.txt encrypted_data.txt AES-128-CBC SHA1 hex:E76B2413958B00E193

decode:
	./crypt_and_hash 1 encrypted_data.txt decrypted_data.txt AES-128-CBC SHA1 hex:E76B2413958B00E193
clear:
	-del *.exe *.o result-enc.txt rsa_priv.txt rsa_pub.txt
	
.PHONY: all clear
	
