# ===== CONFIG =====
OPENSSL_ROOT = /opt/oqs-openssl

CC = gcc
CFLAGS = -Wall -O2 -I$(OPENSSL_ROOT)/include
LDFLAGS = -L$(OPENSSL_ROOT)/lib64 -Wl,-rpath=$(OPENSSL_ROOT)/lib64 -lssl -lcrypto -lpthread

SERVER = server
CLIENT = client

# ===== BUILD =====
all: $(SERVER) $(CLIENT)

$(SERVER): server.c
	$(CC) $(CFLAGS) -o $(SERVER) server.c $(LDFLAGS)

$(CLIENT): client.c
	$(CC) $(CFLAGS) -o $(CLIENT) client.c $(LDFLAGS)


pqc-all:
	$(CC) $(CFLAGS) pqc_server.c -o server $(LDFLAGS)
	$(CC) $(CFLAGS) pqc_bot.c -o bot $(LDFLAGS)

pqc-gen:
	$(CC) $(CFLAGS) -Wextra -O0 pqc_gen.c -o pqc_gen $(LDFLAGS)
	LD_LIBRARY_PATH=$(OPENSSL_ROOT)/lib64 ./pqc_gen mldsa44 server.crt server.key

# ===== MININET =====
mininet: pqc-all
	sudo python3 controller.py --bots 5 --threads 10 --duration 30

mininet-interactive: pqc-all
	sudo python3 controller.py --interactive --bots 2

# ===== CLEAN =====
clean:
	rm -f $(SERVER) $(CLIENT) server bot pqc_gen metrics.csv