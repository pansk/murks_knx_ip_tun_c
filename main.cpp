#include<WinSock2.h> // connect, socket, sendto
#include<string.h> // memset
#include<stdio.h> // printf
#include<cstdint> // close, uintX_t
#include<stdlib.h> // malloc
#include<assert.h> // assert

const char* target_multicast = "224.0.23.12";

#include"knx_ip_tun.h"
#include"tgrm_handler.h"

#include <ws2tcpip.h>


int handle_frame(void* frame, size_t sz){
    knx_ip_header* knxip_header;
	knxip_header = (knx_ip_header *)frame;
	assert(sz == ntohs(knxip_header->length));

	tgrm_handler_execute(ntohs(knxip_header->service_type),
		(char*)frame + sizeof(knx_ip_header),
		sz - sizeof(knx_ip_header));

	return ntohs(knxip_header->service_type);
}

void test_send_cemi(void* p_channel){
	uint8_t data[] = { 0x80 };
    knx_frame_segment s = {.data = &data, .size = 1, .next = NULL};
	printf("test send cemi\n");
	knx_ip_tun_send_cemi(&s, 0x0017, 1, p_channel);
}

/* handler for "search response" KNXnet/IP frames. Fills struct sockaddr_in
 * pointed to by ret_buf, so this may be directly used to connect to host */
void handler_search_autodisc(void* frame, size_t sz, void* ret_buf){
    sockaddr_in* a = (struct sockaddr_in*) ret_buf;
    knx_ip_hpai_4* hpai = (knx_ip_hpai_4 *)frame;
	assert(sz >= sizeof(knx_ip_hpai_4));
	if(hpai->proto_code != 0x01) return;

	printf("\tdetected UDP addr %u.%u.%u.%u port %u\n",
		((uint8_t*) &hpai->address)[0], ((uint8_t*) &hpai->address)[1],
		((uint8_t*) &hpai->address)[2], ((uint8_t*) &hpai->address)[3],
		ntohs(hpai->port));

	if(ret_buf != NULL){
		a->sin_port=hpai->port;
		a->sin_addr.s_addr=hpai->address;
	}
}

int target_search(sockaddr_in* remote){
    sockaddr_in r_multicast={
		.sin_family=AF_INET,
		.sin_port=htons(3671)};
	inet_pton(AF_INET, target_multicast, &r_multicast.sin_addr.s_addr);
	void* frame;
	SOCKET sfd;
	size_t r;

#pragma pack(push, 1)
	struct knx_ip_search_req_4 {
        knx_ip_header knx_ip_header;
        knx_ip_hpai_4 hpai;
	} rq;
#pragma pack(pop)

	rq.knx_ip_header.header_length = sizeof(knx_ip_header); //0x06
	rq.knx_ip_header.knxip_version = 0x10;
	rq.knx_ip_header.service_type = htons(0x0201); // search req.
	rq.knx_ip_header.length = htons(sizeof(knx_ip_header) +
		sizeof(knx_ip_hpai_4));
	// control endpoint
	rq.hpai.length = sizeof(knx_ip_hpai_4); // 0x08
	rq.hpai.proto_code = 0x01; // IPv4 UDP: 0x01, TCP: 0x02
	rq.hpai.address = 0x00000000;
	rq.hpai.port = 0x0000;

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sfd == -1) return 1;

	r = sendto(sfd, (const char *)&rq, sizeof(struct knx_ip_search_req_4), 0,
			(sockaddr*) &r_multicast, sizeof(sockaddr_in));
	printf("mulicast search sent (%zx B)\n", r);

	memset(remote, 0x00, sizeof(sockaddr_in));
	remote->sin_family=AF_INET;
	tgrm_handler_reg(KNX_ST_SEARCH, handler_search_autodisc, remote);

	frame = malloc(1024);
	while(r>0){
		r = recv(sfd, (char *)frame, 1024, 0); // FIXME: Timeout
		//r = recvfrom(sfd, frame, 1024, 0, NULL, 0);
		if(((signed int) r) <= 0) break;

		if(handle_frame(frame, r) == KNX_ST_SEARCH) {
			closesocket(sfd);
			tgrm_handler_allfree();
			return 0;
		}
	}

	closesocket(sfd);
	tgrm_handler_allfree();
	return 1;
}

int str_target(char* host, char* pport, sockaddr_in* remote){
	int port = atoi(pport);
//	char* host = malloc(strlen(phost));
	
	assert(port <= 0xffff && port > 0);
	
	remote->sin_family = AF_INET;
	remote->sin_port = htons(port); // FIXME: ensure endianness!
	inet_pton(AF_INET, host, &remote->sin_addr.s_addr);

	assert(remote->sin_addr.s_addr != 0);

	return 0;
}


int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv){
	WSADATA wsadata{};
	WSAStartup(MAKEWORD(2, 2), &wsadata);
    sockaddr_in remote,local;
	int local_sz;
	SOCKET sfd; // socket
	unsigned int i;
	size_t r = 1;
	static knx_ip_channel channel = {.sock = INVALID_SOCKET,
		.seq_recv=0, .seq_send=0, .active = 0};

	void* buf;
	fd_set rfds;
    timeval select_tv={.tv_sec=50, .tv_usec=0};
	int select_ret;

	// initialize socket
	memset(&remote, 0x00, sizeof(sockaddr_in));
	memset(&local, 0x00, sizeof(sockaddr_in));

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sfd == -1) return 1;
	channel.sock = sfd;

	if(argc >= 3){
		// tunnel host specified
		if( str_target(argv[1], argv[2], &remote) ){
			printf("invalid host");
			return 1;
		}
	}else {
		// do multicast search
		target_search(&remote);
	}


	if(connect(sfd, (const sockaddr*) &remote,
			sizeof(sockaddr_in)))
		return 3;

	local_sz=sizeof(sockaddr_in);
	if(getsockname(sfd, (sockaddr*) &local, &local_sz) ||
			local_sz > sizeof(sockaddr_in) )
		return 4;

	printf("local %hhu.%hhu.%hhu.%hhu port %hu\n",
		((uint8_t*) &local.sin_addr.s_addr)[0],
		((uint8_t*) &local.sin_addr.s_addr)[1],
		((uint8_t*) &local.sin_addr.s_addr)[2],
		((uint8_t*) &local.sin_addr.s_addr)[3],
		ntohs(local.sin_port));

	channel.hpai.length = sizeof(knx_ip_hpai_4);
	channel.hpai.proto_code = 0x01;
	channel.hpai.address = local.sin_addr.s_addr;
	channel.hpai.port = local.sin_port;

	knx_ip_tun_send_request(&channel);

	tgrm_handler_reg(KNX_ST_TUN, knx_ip_handler_tunnel, &channel);
	tgrm_handler_reg(KNX_ST_DISCO, knx_ip_handler_disco, &channel);
	tgrm_handler_reg(KNX_ST_CONNRES, knx_ip_handler_connres, &channel);
	tgrm_handler_reg(KNX_ST_CSRES, knx_ip_handler_csres, &channel);

	buf = malloc(1024);
	while(r>0) {
		FD_ZERO(&rfds);
		FD_SET(sfd, &rfds);
		//FD_SET(0, &rfds);
		select_ret = select(sfd+1, &rfds, NULL, NULL, &select_tv);
		if (select_ret == -1){ printf("error on select"); } // FIXME
		else if (select_ret){
			if(FD_ISSET(sfd, &rfds)){
				// TODO: timeout, keepalive
				r = recv(sfd, (char*)buf, 1024, 0);
				if(((signed int) r) <= 0) break;
				printf("frame 0x%zx Bytes: \n\t", r);
				for(i=0; i<r; i++) printf("%02x", ((uint8_t*) buf)[i]);
				printf("\n");

				switch(handle_frame(buf, r)){
					case KNX_ST_DISCO:
						r=0;
						break;
					case KNX_ST_DISCO_RET:
						r=0;
						break;
					case KNX_ST_CSRES:
					default:
						select_tv.tv_sec=60;
						select_tv.tv_usec=0;
				}
			//} else if(FD_ISSET(0, &rfds)){
			//	r = read(0, buf, 1023);
			//	((char*) buf)[r] = '\0';
			//	printf("entered line: %s\n", (char*) buf);
			//	if(strncmp((char*)buf, "disconnect", strlen("disconnect")) == 0)
			//		knx_ip_send_disconnect(&channel);
			//	if(strncmp((char*)buf, "test", strlen("test")) == 0)
			//		test_send_cemi(&channel);
			}
		} else{
			printf("timeout ... send csr frame (keepalive)\n");
			knx_ip_send_control_rq(&channel, 0x0207, "keepalive");
			select_tv.tv_sec=10;
			select_tv.tv_usec=0;
		}
	}

	tgrm_handler_allfree();
	free(buf);

	closesocket(sfd);
	return 0;
}
