
HEADERS = cs472-proto.h
CFLAGS = -g -Wall -lpthread
CC = gcc

all: app2proxy

app2proxy: main.o mongoose.o
	$(CC) $(CFLAGS) main.o mongoose.o -o app2proxy

main.o: main.c mongoose.h
	$(CC) $(CFLAGS) -c main.c -o main.o

mongoose.o: mongoose.c
	$(CC) $(CFLAGS) -c mongoose.c -o mongoose.o

clean:
	rm *.o
	rm ./app2proxy
