CC = clang
CFLAGS = -Wall -Wextra
LDFLAGS = -pthread -lcapstone -lunicorn

all: emuhookdetector_static emuhookdetector_dynamic

emuhookdetector_static: emuhookdetector.o
	${CC} ${CFLAGS} -static $^ -o $@ ${LDFLAGS} -lm

emuhookdetector_dynamic: emuhookdetector.o
	${CC} ${CFLAGS} $^ -o $@ ${LDFLAGS}

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@

.PHONY: clean
clean:
	rm -f *.o emuhookdetector_static emuhookdetector_dynamic report.txt
