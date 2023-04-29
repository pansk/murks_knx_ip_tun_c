
#include <cstring> // memset
#include <cstdio> // printf
#include <cstdint> // close, uintX_t
#include <cassert> // assert
#include <iostream>
#include <cstring>

#include <WinSock2.h> // connect, socket, sendto
#include <ws2tcpip.h>

#include"knx_ip_tun.h"

const char* target_multicast = "224.0.23.12";

void test_send_cemi(knx_ip_channel* channel){
	uint8_t data[]{ 0x80 };
    knx_frame_segment s{
        .data = &data,
        .size = 1,
        .next = nullptr
    };
	printf("test send cemi\n");
	channel->tun_send_cemi(&s, 0x0017, 1);
}



int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv){
	WSADATA wsadata{};
	WSAStartup(MAKEWORD(2, 2), &wsadata);
    // socket
    size_t r = 1;
	knx_ip_channel channel{};

	char buf[1024];
	fd_set rfds;
    timeval select_tv={.tv_sec=50, .tv_usec=0};

	assert(argc >= 3);
    // initialize socket
    const int retval = channel.connect(argv[1], atoi(argv[2]));
	if (retval != 0) { return retval; }

	while(r>0) {
		const int fds = channel.socket();
		FD_ZERO(&rfds);
		FD_SET(fds, &rfds);
		//FD_SET(0, &rfds);

        const int select_ret = select(fds + 1, &rfds, nullptr, nullptr, &select_tv);
		if (select_ret == -1)
		{
		    printf("error on select");
		} // FIXME
		else if (select_ret){
			if (FD_ISSET(channel.socket(), &rfds)) {
				// TODO: timeout, keepalive
				if (channel.receive())
				{
					select_tv.tv_sec = 60;
					select_tv.tv_usec = 0;
				} else
				{
					r = 0;
				}

			} else if(FD_ISSET(0, &rfds)){
				r = fread(buf, 1, 1023, stdin);
				buf[r] = '\0';
				printf("entered line: %s\n", buf);
				if(strncmp(buf, "disconnect", strlen("disconnect")) == 0)
					channel.send_disconnect();
				if(strncmp(buf, "test", strlen("test")) == 0)
					test_send_cemi(&channel);
			}
		} else{
			printf("timeout ... send csr frame (keepalive)\n");
			channel.send_control_rq(KNX_ST::KEEPALIVE);
			select_tv.tv_sec=10;
			select_tv.tv_usec=0;
		}
	}

	return 0;
}
