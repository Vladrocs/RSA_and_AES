FLAGS = -Wall
INCLUDE_PATH = -I../include
LIBS_PATH = -L ../lib
LIBS = -lmbedtls -lmbedx509 -lmbedcrypto

all: rsa_decrypt.exe rsa_encrypt.exe rsa_genkey.exe
	
%.o: %.c 
	gcc -c $(INCLUDE_PATH) $< -o $@
	
%.exe: %.o
	gcc $(THIRDPARTY_INCLUDES) $< $(LIBS_PATH) $(LIBS) $(MBEDTLS_TEST_OBJS) -o $@

run:
	./rsa_genkey.exe
	./rsa_encrypt.exe $(MSG) 
	echo "Textul criptat este: "
	type "result-enc.txt"
	./rsa_decrypt.exe 

clear:
	-del *.exe *.o result-enc.txt rsa_priv.txt rsa_pub.txt
	
.PHONY: all clear
	
