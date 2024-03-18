all: ciphers kv

ciphers:
	gcc Ciphers/demo.c Ciphers/cs457_crypto.c -o ciphers

kv:
	gcc KV_Store/kv_store.c -o kv -lssl -lcrypto
clean:
	rm -f ciphers kv