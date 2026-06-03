all: injector-amd64.bin pcce

injector-amd64.bin: injector.c
	gcc -c -O2 -fPIC -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables -o injector.o injector.c
	ld -N -shared -nostdlib -e _start -o injector-amd64.bin injector.o
	rm -f injector.o

pcce: injector-amd64.bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pcce .

clean:
	rm -f injector.o injector-amd64.bin pcce

.PHONY: all clean
