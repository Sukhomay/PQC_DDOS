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


pqc-all: pqc_server pqc_client
	$(CC) $(CFLAGS) pqc_bot.c -o bot $(LDFLAGS)

pqc_server: pqc_server.c SETUP.h
	$(CC) $(CFLAGS) pqc_server.c -o pqc_server $(LDFLAGS)

pqc_client: pqc_client.c SETUP.h
	$(CC) $(CFLAGS) pqc_client.c -o pqc_client $(LDFLAGS)

pqc-gen: pqc_gen.c
	$(CC) $(CFLAGS) -Wextra -O0 pqc_gen.c -o pqc_gen $(LDFLAGS)
	LD_LIBRARY_PATH=$(OPENSSL_ROOT)/lib64 ./pqc_gen server.crt server.key

# ===== MININET =====
mininet: pqc-all
	sudo python3 controller.py --bots 5 --threads 10 --duration 30

mininet-interactive: pqc-all
	sudo python3 controller.py --interactive --bots 2

# ===== CLEAN =====
clean:
	rm -f $(SERVER) $(CLIENT) server pqc_server bot pqc_client pqc_gen metrics.csv client_metrics.csv