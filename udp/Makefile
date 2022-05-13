
SRC_DIR = $(shell pwd)

CC    := $(COMPILER_PREFIX)gcc
CXX   := $(COMPILER_PREFIX)g++
AR    := $(COMPILER_PREFIX)ar
STRIP := $(COMPILER_PREFIX)strip

DESTDIR ?= ./bin


SOURCES   := udp_server.c \
             udp_client.c

INCLUDES  :=

DEFS := -DSOCKET_IPV6

CFLAGS += -Wall \
          -fPIC \
          -g

LDFLAGS :=

OBJ_DIR := obj

OBJ_LIB :=

INC_DIR := -I$(SRC_DIR)

OBJ_CFLAGS := $(INC_DIR) \
              -c \
              $(CFLAGS)

OBJ_LDFLAGS := $(LDFLAGS) \
               $(LIB_PATH)


OBJ_SRC    := $(SOURCES:%.c=$(OBJ_DIR)/%.o)

.PHONY: bin client server clean all

bin :
	make client
	make server
	install -d $(SRC_DIR)/bin
	install -m 755 $(OBJ_DIR)/udp_client $(SRC_DIR)/bin
	install -m 755 $(OBJ_DIR)/udp_server $(SRC_DIR)/bin

all :
	make clean
	make bin

server : $(OBJ_DIR)/udp_server
	@md5sum $< > $<.md5

client : $(OBJ_DIR)/udp_client
	@md5sum $< > $<.md5

$(OBJ_DIR)/udp_client :  $(OBJ_DIR)/udp_client.o
	$(CC) -o $@ $< $(OBJ_LIB) $(OBJ_LDFLAGS) -Wl,-Map=$@.map

$(OBJ_DIR)/udp_server : $(OBJ_DIR)/udp_server.o
	$(CC) -o $@ $< $(OBJ_LIB) $(OBJ_LDFLAGS) -Wl,-Map=$@.map

$(OBJ_DIR)/%.o : %.c
	@echo "mkdir $(OBJ_DIR)..."
	@mkdir -p $(SRC_DIR)/$(OBJ_DIR)
	$(CC) $(DEFS) $(OBJ_CFLAGS) -o $@ $<

clean:
	@echo "Clean $(SRC_DIR)/$(OBJ_DIR)..."
	@rm -rvf $(SRC_DIR)/$(OBJ_DIR)
	@rm -rvf $(SRC_DIR)/bin

install:
	@echo "DEST Path = $(DESTDIR)"
	install -d $(DESTDIR)
	install -m 755 $(OBJ_DIR)/udp_client $(DESTDIR)
	install -m 755 $(OBJ_DIR)/udp_server $(DESTDIR)

uninstall:
	@echo "DEST Path = $(DESTDIR)"
	@rm -rvf $(DESTDIR)


