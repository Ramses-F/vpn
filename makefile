# Compilateur et flags
CC = gcc
CFLAGS = -Wall -Wextra -g -fsanitize=address -Iinclude
LDFLAGS = -lssl -lcrypto -fsanitize=address

# Dossier source et build
SRC_DIR = src
BUILD_DIR = build

# Liste des fichiers sources
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Noms des objets dans build (ex: src/main.c -> build/main.o)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# Nom de l'exécutable
TARGET = $(BUILD_DIR)/myvpn

.PHONY: all clean debug

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compilation des .c en .o dans build/
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Edition de lien
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Nettoyage
clean:
	rm -rf $(BUILD_DIR)/*

# Cible spéciale pour debug (compile avec symboles -g)
debug: CFLAGS = -Wall -Wextra -g -O0 -Iinclude
debug: clean all
