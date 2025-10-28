# Compiler and flags
CC = gcc
CFLAGS = -Wall -lm -lpthread -lcrypto -lssh

# Executable names
CLIENT_EXEC = client
SERVER_EXEC = server

# Source files
CLIENT_SRC = client.c
SERVER_SRC = server.c

# Default target
.PHONY: all
all: build

# Compile individual components
compile-client:
	$(CC) $(CLIENT_SRC) -o $(CLIENT_EXEC) $(CFLAGS)

compile-server:
	$(CC) $(SERVER_SRC) -o $(SERVER_EXEC) $(CFLAGS)

# Build both client and server
.PHONY: build
build: compile-client compile-server
	@echo "Build completed successfully!"