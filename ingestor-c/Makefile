# ==============================================================================
# Cerberus — Head 1: C11 Ingestor Makefile
# ==============================================================================

CC       ?= cc
CFLAGS   := -std=c11 -Wall -Wextra -Werror -pedantic -O2 -Iinclude -Ivendor
SQLITE_FLAGS := -O2 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1 -DSQLITE_THREADSAFE=1 -Ivendor
LDFLAGS  := -lpthread -ldl -lm

BUILD_DIR := build
BIN_DIR   := bin
TARGET    := $(BIN_DIR)/cerberus-ingestor
TEST_BIN  := $(BIN_DIR)/test-ingestor

SQLITE_OBJ   := $(BUILD_DIR)/sqlite3.o
INGESTOR_OBJ := $(BUILD_DIR)/ingestor.o
MAIN_OBJ     := $(BUILD_DIR)/main.o
TEST_OBJ     := $(BUILD_DIR)/test_ingestor.o

.PHONY: all clean test

all: $(TARGET)

$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

# Compile SQLite3 amalgamation once with FTS5 and JSON1 enabled
$(SQLITE_OBJ): vendor/sqlite3.c vendor/sqlite3.h | $(BUILD_DIR)
	$(CC) $(SQLITE_FLAGS) -c vendor/sqlite3.c -o $(SQLITE_OBJ)

# Compile Cerberus C11 modules with strict flags (-std=c11 -Wall -Wextra -Werror -pedantic -O2)
$(INGESTOR_OBJ): src/ingestor.c include/cerberus_ingestor.h vendor/sqlite3.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c src/ingestor.c -o $(INGESTOR_OBJ)

$(MAIN_OBJ): src/main.c include/cerberus_ingestor.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c src/main.c -o $(MAIN_OBJ)

$(TEST_OBJ): tests/test_ingestor.c include/cerberus_ingestor.h vendor/sqlite3.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c tests/test_ingestor.c -o $(TEST_OBJ)

$(TARGET): $(SQLITE_OBJ) $(INGESTOR_OBJ) $(MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(SQLITE_OBJ) $(INGESTOR_OBJ) $(MAIN_OBJ) -o $(TARGET) $(LDFLAGS)

$(TEST_BIN): $(SQLITE_OBJ) $(INGESTOR_OBJ) $(TEST_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(SQLITE_OBJ) $(INGESTOR_OBJ) $(TEST_OBJ) -o $(TEST_BIN) $(LDFLAGS)

test: $(TARGET) $(TEST_BIN)
	@rm -f $(BUILD_DIR)/test_cerberus.db $(BUILD_DIR)/test_cerberus.db-wal $(BUILD_DIR)/test_cerberus.db-shm
	./$(TARGET) --db $(BUILD_DIR)/test_cerberus.db --schema ../schema/schema.sql --self-test
	@rm -f $(BUILD_DIR)/test_cerberus.db $(BUILD_DIR)/test_cerberus.db-wal $(BUILD_DIR)/test_cerberus.db-shm
	./$(TEST_BIN)
	python3 tests/test_security_ingestor.py

clean:
	rm -rf $(BUILD_DIR)/ingestor.o $(BUILD_DIR)/main.o $(BUILD_DIR)/test_ingestor.o $(BIN_DIR)
