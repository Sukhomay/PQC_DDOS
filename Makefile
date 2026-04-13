# ===== CONFIG =====
OPENSSL_ROOT = $(HOME)/oqs/openssl

CC = gcc
CFLAGS = -Wall -O2 -I$(OPENSSL_ROOT)/include
LDFLAGS = -L$(OPENSSL_ROOT)/lib64 -lssl -lcrypto -lpthread

SERVER = server
CLIENT = client

# ===== BUILD =====
all: $(SERVER) $(CLIENT)

$(SERVER): server.c
	$(CC) $(CFLAGS) -o $(SERVER) server.c $(LDFLAGS)

$(CLIENT): client.c
	$(CC) $(CFLAGS) -o $(CLIENT) client.c $(LDFLAGS)


pqc-all:
	LD_LIBRARY_PATH=$HOME/oqs/openssl/lib64:$HOME/oqs/openssl/lib \
	OPENSSL_MODULES=$HOME/oqs/openssl/lib64/ossl-modules \
	OPENSSL_CONF=$HOME/oqs/openssl/ssl/openssl.cnf \
	
	gcc pqc_server.c -o server -lssl -lcrypto -lpthread
	gcc pqc_bot.c -o bot -lssl -lcrypto -lpthread

pqc-gen:
	gcc -Wall -Wextra -O0 -I$HOME/oqs/openssl/include pqc_gen.c -L$HOME/oqs/openssl/lib64 -lssl -lcrypto -o pqc_gen

	LD_LIBRARY_PATH=$HOME/oqs/openssl/lib64:$HOME/oqs/openssl/lib \
	OPENSSL_MODULES=$HOME/oqs/openssl/lib64/ossl-modules \
	OPENSSL_CONF=$HOME/oqs/openssl/ssl/openssl.cnf \
	./pqc_gen mldsa44 server.crt server.key


# ===== CLEAN =====
clean:
	rm -f $(SERVER) $(CLIENT) server bot pqc_gen