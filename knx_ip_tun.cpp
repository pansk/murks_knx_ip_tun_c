#include "knx_ip_tun.h"
#include <cstdio>
#include <cstdlib> // malloc/free
#include <WinSock2.h> // send
#include <cstring> // memcpy
#include <cassert>
#include <iostream>
#include <limits>
#include <ws2tcpip.h>

#pragma pack(push, 1)
struct cemi_start {
	KNX_CEMI_MC message_code; // message code
	uint8_t additional_information_length; // addditional information length
};

struct cemi_data {
	uint8_t control_1;
	uint8_t control_2;
	knx_ia_t source_address;
	knx_ia_t destination_address;
	uint8_t data_length;
};

struct connect_request_information { /* connect request information */
	uint8_t length;
	uint8_t type;
	uint8_t layer;
	uint8_t reserved;
	//	hostproto_indep_data;
	//	hostproto_dep_data;
};
#pragma pack(pop)

char knx_print_prio_char(uint8_t c1){
    const uint8_t p = c1 & KNX_CTRL1_PRIO;
	return (p == KNX_CTRL1_PL)?'L':(
			(p == KNX_CTRL1_PN)?'N':(
				(p == KNX_CTRL1_PU)?'U':'S'));
}
char* knx_print_ia(knx_ia_t na, char* s){
    const uint16_t a = ntohs(na);
	snprintf(s, 10, "%d.%d.%d", (a & 0xf000) >> 12,
		(a & 0x0f00) >> 8, (a & 0x00ff));
	return s;
}
char* knx_print_ga(knx_ia_t na, char* s){
    const uint16_t a = ntohs(na);
	snprintf(s, 10, "%d/%d/%d", (a & 0xf000) >> 12,
		(a & 0x0f00) >> 8, (a & 0x00ff));
	return s;
}

void knx_ip_channel::tun_send_request() {
	connect_request_information cri{
		.length = sizeof(connect_request_information), // 0x04
		.type = 0x04, // TUNNEL_CONNECTION = 0x04
		.layer = 0x02, // TUNNEL_LINKLAYER = 0x02
		.reserved = 0x00, // 0x00
	};

    knx_frame_segment s_cri{
        .data = &cri,
        .size = sizeof(connect_request_information),
		.next = nullptr
    }; /* last segment */
    knx_frame_segment s_data{
        .data = &hpai_,
		.size = sizeof(knx_ip_hpai_4),
        .next = &s_cri
    }; /* second segement */
    knx_frame_segment s_ctrl{
        .data = &hpai_,
		.size = sizeof(knx_ip_hpai_4),
        .next = &s_data
    }; /* first segment */

	assert(hpai_.length == sizeof(knx_ip_hpai_4));

	send_frame(KNX_ST::CONNREQ, &s_ctrl);
}


void knx_ip_channel::tun_send_ack(uint8_t seq_nr) const {
#pragma pack(push, 1)
	struct f {
         knx_ip_header knx_ip_header;
         knx_ip_tun_conn_header ch;
	};
#pragma pack(pop)
	const f b{
		.knx_ip_header{
			.header_length = sizeof(knx_ip_header), //0x06
			.knxip_version = 0x10,
			.service_type = KNX_ST::TUN_ACK, // tun ack
			.length = htons(sizeof(f)),
		},
		.ch {
	        .length = sizeof(knx_ip_tun_conn_header), // 0x04
	        .channel = channel_,
	        .seq = seq_nr,
	        .resvd = 0x00,
		},
	};

	send(sock_, reinterpret_cast<const char*>(&b), sizeof(b), 0);
	printf("\tframe acked\n");
}

void knx_ip_channel::send_control_rq(KNX_ST st) const {
#pragma pack(push, 1)
    struct f {
        knx_ip_header header;
        uint8_t channel;
        uint8_t resvd;
        knx_ip_hpai_4 hpai;
    };
#pragma pack(pop)

	const f b{
		.header{
			.header_length = sizeof(knx_ip_header), //0x06
			.knxip_version = 0x10,
			.service_type = st,
			.length = htons(sizeof(f)),
		},
		.channel = channel_,
		.resvd = 0x00,
		.hpai = hpai_,
	};

	send(sock_, reinterpret_cast<const char*>(&b), sizeof(b), 0);
	printf("send_control_rq %hu sent\n", st);
}

/* assemble knx frame segements into single frame.
 * Arguments: first frame segement as struct knx_frame_segment, linking to
 * all other segements of frame. Segements are assembled in order, i.e.
 * segement directly addressed by `segs` argument first.
 * Input segements have to be freed separatly afterwards, to allow for them to
 * reside in stack and heap. The resulting frame will be malloc'ed
 * and must be freed after use. Return is struct knx_frame_segement since this
 * enables providing the size of allocated memory. */
knx_frame_segment knx_frame_assemble(const knx_frame_segment* seg){
	size_t size = 0;
	size_t offset = 0;

	for(const knx_frame_segment* s = seg; s != nullptr; s = s->next) size += s->size;

    const auto data = static_cast<char*>(malloc(size));
	for(const knx_frame_segment* s = seg; s != nullptr; s = s->next) {
		memcpy(data + offset, s->data, s->size);
		offset += s->size;
	}
	return {
	    .data = data,
	    .size = size,
	    .next = nullptr
	};
}

void knx_ip_channel::send_frame(KNX_ST st, knx_frame_segment* seg) const {
	knx_ip_header header{
		.header_length = sizeof(knx_ip_header), //0x06
		.knxip_version = 0x10,
		.service_type = st,
		.length = 0 // ensure all memory is zeroed
	};
    const knx_frame_segment hs{
        .data = &header,
		.size = sizeof(knx_ip_header),
        .next = seg
    };

	/* knx_ip_header.length can not be set here, because final overall frame
	 * size is not known yet. */

    const knx_frame_segment frame = knx_frame_assemble(&hs);
	/* map start of final frame data to knx ip header, to be able to set
	 * overall frame length */
    const auto frame_knx_ip_header = static_cast<knx_ip_header*>(frame.data);
	assert(frame.size <= std::numeric_limits<uint16_t>::max());

    const uint16_t frame_size = static_cast<uint16_t>(frame.size);

	frame_knx_ip_header->length = htons(frame_size);

	send(sock_, static_cast<const char*>(frame.data), frame_size, 0);

	printf("frame sent\n");
	free(frame.data);
}

void knx_ip_channel::tun_send_frame(KNX_ST st, knx_frame_segment* seg) {
	knx_ip_tun_conn_header ch{
	    .length = sizeof(knx_ip_tun_conn_header), // 0x04
	    .channel = channel_,
	    .seq = seq_send_,
	    .resvd = 0x00,
	};

    knx_frame_segment ch_s{
        .data = &ch,
		.size = sizeof(knx_ip_tun_conn_header),
        .next = seg
    };

	send_frame(st, &ch_s);
	seq_send_++;
}

void knx_ip_channel::send_disconnect(){
	send_control_rq(KNX_ST::DISCONNECT);
	active_ = connection_status::disconnecting; // TODO: transform to inactive to make active_ = false
}

void knx_ip_tun_parse_cemi(const char* frame, size_t sz){
	char src_addr[10];
	char dst_addr[10];

	// todo: evaluate mc first

	assert(sz >= sizeof(cemi_start));

    const auto start = reinterpret_cast<const cemi_start*>(frame);
    const auto data = reinterpret_cast<const cemi_data*>(frame + sizeof(cemi_start) + start->additional_information_length);

	if(start->message_code != KNX_CEMI_MC::DATA_IND
			&& start->message_code != KNX_CEMI_MC::DATA_REQ ) {
		printf("unknown cemi message code 0x%02x\n", start->message_code);
		return;
	}
	assert(sz >= sizeof(cemi_start) + start->additional_information_length +
		sizeof(cemi_data));
    const auto tpdu = reinterpret_cast<const uint8_t*>(frame + sizeof(cemi_start) + sizeof(cemi_data));

	assert(sz >= sizeof(cemi_start) + start->additional_information_length +
		sizeof(cemi_data) + data->data_length);

	printf("\t\t");
	for(size_t i=0; i < sz; i++) printf("%02x", reinterpret_cast<const uint8_t*>(frame)[i]);
	printf("\n");

	printf("\tmc: 0x%02x, npdu length: 0x%02x (+1 +0x%02x addil), tpci %02x\n",
		start->message_code, data->data_length, start->additional_information_length,
		tpdu[0]);
	printf("\tFT: %c rpt: %c bcst: %c prio: %c ack: %c cf: %c ",
		data->control_1 & KNX_CTRL1_FT ?'S':'E', // standard frame
		(data->control_1 & KNX_CTRL1_R)?'N':'T', // Repeat
		(data->control_1 & KNX_CTRL1_SB)?'D':'S',
		knx_print_prio_char(data->control_1),
		(data->control_1 & KNX_CTRL1_A)?'T':'N',
		(data->control_1 & KNX_CTRL1_C)?'T':'N');
	printf("AT: %c, HC: %d%s\n", data->control_2 & KNX_CTRL2_AT ?'G':'I',
		(data->control_2 & KNX_CTRL2_HC) >> KNX_CTRL2_HC_S,
		(data->control_2 & KNX_CTRL2_EFF) ? ", EFF":"");
	printf("\t%s -> %s\n", knx_print_ia(data->source_address, src_addr),
		(data->control_2 & KNX_CTRL2_AT)
		?  knx_print_ga(data->destination_address, dst_addr)
		: knx_print_ia(data->destination_address, dst_addr));

	printf("\tdata: ");
	for(size_t i=0; i < data->data_length; i++)
		printf("%02x", tpdu[i+1]);
	printf("\n");
}

/* send CEMI frame to tunnel endpoint
 * send `data` to `dest`. `dest` is group address if `group` true */
void knx_ip_channel::tun_send_cemi(knx_frame_segment* data, knx_ia_t dest, int group) {
#pragma pack(push, 1)
	struct h {
		cemi_start start;
		cemi_data data;
		uint8_t tpci;
	};
#pragma pack(pop)
	h header{
		.start{
			.message_code = KNX_CEMI_MC::DATA_REQ,
			.additional_information_length = 0,
		},
		.data{
	        .control_1 = KNX_CTRL1_FT | KNX_CTRL1_R | KNX_CTRL1_SB | KNX_CTRL1_PL,
	        .control_2 = (uint8_t)((group ? KNX_CTRL2_AT : 0) | (6 << KNX_CTRL2_HC_S)),
	        .source_address = ia_,
	        .destination_address = htons(dest),
		    .data_length = uint8_t(data->size),
		},
		.tpci = 0x00,
	};
    knx_frame_segment seg_header{
        .data = &header,
		.size = sizeof(header),
        .next = data
    };
	
	assert(data->size <= std::numeric_limits<uint8_t>::max());

    const knx_frame_segment test_frame = knx_frame_assemble(&seg_header);
	knx_ip_tun_parse_cemi((const char*)test_frame.data, test_frame.size);
	free(test_frame.data);
	tun_send_frame(KNX_ST::TUN, &seg_header);
}

bool knx_ip_channel::receive()
{
	char buf[1024];
	int r = recv(sock_, buf, sizeof(buf), 0);
	if (r <= 0) return false;
	//printf("frame 0x%zx Bytes: \n\t", r);
	for (int i = 0; i < r; i++) printf("%02x", ((uint8_t*)buf)[i]);
	//printf("\n");
	switch (handle_frame(buf, r)) {
	    case KNX_ST::DISCONNECT:
	    case KNX_ST::DISCONNECT_RET:
			return false;
	    case KNX_ST::CSRES:
	    default:
			return true;
	}

}

void knx_ip_channel::disconnect() {
	active_ = connection_status::disconnected;
	closesocket(sock_);
	sock_ = INVALID_SOCKET;
}


void knx_ip_channel::handler_tunnel(const char* frame, size_t sz) {
    const auto chead = reinterpret_cast<const knx_ip_tun_conn_header*>(frame);

	assert(sz >= sizeof(knx_ip_tun_conn_header));
	assert(chead->length == sizeof(knx_ip_tun_conn_header));

	knx_ip_tun_parse_cemi(frame + chead->length, sz - chead->length);

	tun_send_ack(chead->seq);
	seq_recv_ = chead->seq;
}

KNX_ST knx_ip_channel::handle_frame(const char* frame, size_t sz)
{
	const knx_ip_header& knxip_header = *reinterpret_cast<const knx_ip_header*>(frame);
	assert(sz == ntohs(knxip_header.length));

	const char* new_frame = frame + sizeof(knx_ip_header);
	const size_t new_size = sz - sizeof(knx_ip_header);
	KNX_ST service_type = knxip_header.service_type; // Conversion will happen here
    switch (service_type) {

		case KNX_ST::TUN: 
			handler_tunnel(new_frame, new_size);
            break;
		case KNX_ST::DISCONNECT: 
            handler_disco(new_frame, new_size);
            break;
		case KNX_ST::CONNRES: 
            handler_connres(new_frame, new_size);
            break;
		case KNX_ST::CSRES: 
			handler_csres(new_frame, new_size);
            break;
        default:
			printf("no handler for svc type %04x\n", (uint16_t)service_type);
			break;
	}
	return service_type;
}

void knx_ip_channel::handler_disco(const char* frame, size_t sz) {
#pragma pack(push, 1)
	struct f {
		uint8_t channel;
		uint8_t resvd;
		knx_ip_hpai_4 hpai;
	};

	struct fs {
		uint8_t channel;
		uint8_t status;
	};
#pragma pack(pop)
    const auto recv = (const f*)frame;
	const fs resp{
	    .channel = recv->channel,
	    .status = 0x00
	}; // FIXME: status
	assert(sz >= sizeof(f));
	assert(recv->channel == channel_);

	send(sock_, (const char*)& resp, sizeof(resp), 0);

	disconnect();
}

void knx_ip_channel::handler_connres(const char* frame, size_t sz) {
#pragma pack(push, 1)
	struct f {
		uint8_t channel;
		uint8_t status;
		knx_ip_hpai_4 hpai;
		struct knx_ip_crd {
			uint8_t length;
			uint8_t type;
			knx_ia_t ia; // FIXME: Union/Typedef knx_ia_t
		} crd;
	};
#pragma pack(pop)
	const auto b = reinterpret_cast<const f*>(frame);

	assert(sz >= sizeof(f));
	assert(active_ == connection_status::not_connected);
	assert(b->crd.type == 0x04);
	if (b->status != 0x00) {
		printf("connection response: FAILED\n");
		return; // not connected properly
	} 
	printf("connection response\n");

	channel_ = b->channel;
	ia_ = b->crd.ia;
	active_ = connection_status::connected;
	seq_recv_ = 0;
	seq_send_ = 0;
}

/* handle connection state response frame */
void knx_ip_channel::handler_csres(const char* frame, size_t sz) {
#pragma pack(push, 1)
	struct f {
		uint8_t channel;
		uint8_t status;
	};
#pragma pack(pop)
    const auto b = reinterpret_cast<const f*>(frame);

	assert(sz >= sizeof(f));
	assert(active_ == connection_status::connected);
	assert(b->status == 0x00);
	if(b->status != 0x00){
		printf("\tkeepalive FAILED\n");
		if(try_ >= 3)
			send_disconnect();
		else try_++;
		return; // not connected properly
	}

	try_ =0;
	printf("\tkeepalive successful\n");
}

int str_target(const char* host, const char* pport, sockaddr_in* remote) {
	const int port = atoi(pport);
	//	char* host = malloc(strlen(phost));

	assert(port <= 0xffff && port > 0);

	remote->sin_family = AF_INET;
	remote->sin_port = htons(port); // ports must be in "network" format
	inet_pton(AF_INET, host, &remote->sin_addr.s_addr);

	assert(remote->sin_addr.s_addr != 0);

	return 0;
}

int knx_ip_channel::connect(const char* host, const char* port)
{
	sockaddr_in remote{}, local{};
	memset(&remote, 0x00, sizeof(sockaddr_in));
	memset(&local, 0x00, sizeof(sockaddr_in));

	sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_ == INVALID_SOCKET) return 1;

	// tunnel host specified
	if (str_target(host, port, &remote)) {
		printf("invalid host");
		return 1;
	}

	if (::connect(sock_, reinterpret_cast<const sockaddr*>(&remote), sizeof(sockaddr_in))) {
		return 3;
	}

	int local_sz = sizeof(sockaddr_in);
	if (getsockname(sock_, (sockaddr*)&local, &local_sz) || local_sz > sizeof(sockaddr_in)) {
		return 4;
	}

	char ip[16];
	inet_ntop(AF_INET, &local.sin_addr.s_addr, ip, sizeof(ip));

	printf("local %s port %hu\n", ip, ntohs(local.sin_port));

	hpai_ = {
		.length = sizeof(knx_ip_hpai_4),
		.proto_code = 0x01,
		.address = local.sin_addr.s_addr,
		.port = local.sin_port,
	};

	tun_send_request();
	return 0;
}