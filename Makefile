# BB84 QKD Simulation v2.1
# Requires: gcc 14+ (C23), pthreads, Linux (mmap, getrandom)

CC     = gcc
STD    = -std=c2x
WARN   = -Wall -Wextra -Wpedantic
OPT    = -O3 -march=native -flto -funroll-loops
DFLAGS = -DNDEBUG
LIBS   = -lpthread

CFLAGS  = $(STD) $(WARN) $(OPT) $(DFLAGS)
SRCS    = bb84_main.c bb84_types.c bb84_sidecar.c bb84_ramstore.c \
          bb84_front.c bb84_lead.c bb84_reconcile.c bb84_rear.c
OBJS    = $(SRCS:.c=.o)
TARGET  = bb84

.PHONY: all clean run asan debug noise

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

run: all
	./$(TARGET)

# Debug -- no opt, full symbols
debug: CFLAGS = $(STD) $(WARN) -O0 -g
debug: clean all

# ASan -- catch memory errors
asan: CFLAGS = $(STD) $(WARN) -O1 -g \
               -fsanitize=address,undefined \
               -fno-omit-frame-pointer
asan: clean all

# Noisy session -- 25% noise exceeds 11% QBER threshold
# REAR should abort with Gate-X
noise: DFLAGS = -DNDEBUG -DNOISE_RATE_N=36000ULL
noise: clean all run

clean:
	rm -f $(OBJS) $(TARGET)