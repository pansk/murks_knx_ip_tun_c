CFLAGS+=-Wall -Wextra

main: main.o knx_ip_tun.o knx_ip_tun.h

clean:
	rm main.o knx_ip_tun.o main
