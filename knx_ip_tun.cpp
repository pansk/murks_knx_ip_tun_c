#include "knx_ip_tun.h"
#include <cstdio>
#include <cstdlib> // malloc/free
#include <WinSock2.h> // send
#include <cstring> // memcpy
#include <cassert>
#include <limits>

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
	uint8_t p = c1 & KNX_CTRL1_PRIO;
	return (p == KNX_CTRL1_PL)?'L':(
			(p == KNX_CTRL1_PN)?'N':(
				(p == KNX_CTRL1_PU)?'U':'S'));
}
char* knx_print_ia(knx_ia_t na, char* s){
	uint16_t a = ntohs(na);
	snprintf(s, 10, "%hd.%hd.%hd", (a & 0xf000) >> 12,
		(a & 0x0f00) >> 8, (a & 0x00ff));
	return s;
}
char* knx_print_ga(knx_ia_t na, char* s){
	uint16_t a = ntohs(na);
	snprintf(s, 10, "%hd/%hd/%hd", (a & 0xf000) >> 12,
		(a & 0x0f00) >> 8, (a & 0x00ff));
	return s;
}

void knx_ip_tun_send_request(knx_ip_channel* channel){
	connect_request_information cri{
		.length = sizeof(connect_request_information), // 0x04
		.type = 0x04, // TUNNEL_CONNECTION = 0x04
		.layer = 0x02, // TUNNEL_LINKLAYER = 0x02
		.reserved = 0x00, // 0x00
	};

    knx_frame_segment s_cri = { .data = &cri, .size = sizeof(connect_request_information),
		.next = NULL }; /* last segment */
    knx_frame_segment s_data = { .data = &channel->hpai,
		.size = sizeof(knx_ip_hpai_4), .next = &s_cri }; /* second segement */
    knx_frame_segment s_ctrl = { .data = &channel->hpai,
		.size = sizeof(knx_ip_hpai_4), .next = &s_data }; /* first segment */

	assert(channel->hpai.length == sizeof(knx_ip_hpai_4));

	knx_ip_send_frame(channel, KNX_ST::CONNREQ, &s_ctrl);
}


void knx_ip_tun_send_ack(knx_ip_channel *channel, uint8_t seq_nr){
#pragma pack(push, 1)
	struct f {
         knx_ip_header knx_ip_header;
         knx_ip_tun_conn_header ch;
	};
#pragma pack(pop)
	f b{
		.knx_ip_header = {
			.header_length = sizeof(knx_ip_header), //0x06
			.knxip_version = 0x10,
			.service_type = KNX_ST::TUN_ACK, // tun ack
			.length = htons(sizeof(f)),
		},
		.ch = {
	        .length = sizeof(knx_ip_tun_conn_header), // 0x04
	        .channel = channel->channel,
	        .seq = seq_nr,
	        .resvd = 0x00,
		},
	};

	send(channel->sock, (const char *)&b, sizeof(b), 0);
	printf("\tframe acked\n");
}

void knx_ip_send_control_rq(knx_ip_channel *channel, KNX_ST rq,
                            const char* rq_name){
#pragma pack(push, 1)
    struct f {
        knx_ip_header header;
        uint8_t channel;
        uint8_t resvd;
        knx_ip_hpai_4 hpai;
    };
#pragma pack(pop)

	f b{
		.header = {
			.header_length = sizeof(knx_ip_header), //0x06
			.knxip_version = 0x10,
			.service_type = rq,
			.length = htons(sizeof(f)),
		},
		.channel = channel->channel,
		.resvd = 0x00,
		.hpai = channel->hpai,
	};

	send(channel->sock, (const char*)&b, sizeof(b), 0);
	printf("%s sent\n", rq_name);
}

/* assemble knx frame segements into single frame.
 * Arguments: first frame segement as struct knx_frame_segment, linking to
 * all other segements of frame. Segements are assembled in order, i.e.
 * segement directly addressed by `segs` argument first.
 * Input segements have to be freed separatly afterwards, to allow for them to
 * reside in stack and heap. The resulting frame will be malloc'ed
 * and must be freed after use. Return is struct knx_frame_segement since this
 * enables providing the size of allocated memory. */
knx_frame_segment knx_frame_assemble(knx_frame_segment* seg){
    knx_frame_segment* s;
    knx_frame_segment r = { .data = NULL, .size = 0, .next = NULL };
	size_t offset = 0;

	for(s = seg; s != NULL; s = s->next) r.size += s->size;
	r.data = malloc(r.size);
	for(s = seg; s != NULL; s = s->next) {
		memcpy((char*)r.data + offset, s->data, s->size);
		offset += s->size;
	}
	return r;
}

void knx_ip_send_frame(knx_ip_channel *channel, KNX_ST st,
                       knx_frame_segment* seg){
	knx_ip_header header{
		.header_length = sizeof(knx_ip_header), //0x06
		.knxip_version = 0x10,
		.service_type = st,
		.length = 0 // ensure all memory is zeroed
	};
    knx_frame_segment hs = {.data = &header,
		.size = sizeof(knx_ip_header), .next = seg};

	/* knx_ip_header.length can not be set here, because final overall frame
	 * size is not known yet. */

	knx_frame_segment frame = knx_frame_assemble(&hs);
	/* map start of final frame data to knx ip header, to be able to set
	 * overall frame length */
    knx_ip_header* frame_knx_ip_header = (knx_ip_header*)frame.data;
	assert(frame.size <= std::numeric_limits<uint16_t>::max());

	uint16_t frame_size = uint16_t(frame.size);

	frame_knx_ip_header->length = htons(frame_size);

	send(channel->sock, (const char *)frame.data, frame_size, 0);
	printf("frame sent\n");
	free(frame.data);
}

void knx_ip_tun_send_frame(knx_ip_channel *channel, KNX_ST st,
                           knx_frame_segment* seg){
	knx_ip_tun_conn_header ch{
	    .length = sizeof(knx_ip_tun_conn_header), // 0x04
	    .channel = channel->channel,
	    .seq = channel->seq_send,
	    .resvd = 0x00,
	};

    knx_frame_segment ch_s = {.data = &ch,
		.size = sizeof(knx_ip_tun_conn_header), .next = seg};


	knx_ip_send_frame(channel, st, &ch_s);
	channel->seq_send++;
}

void knx_ip_send_disconnect(knx_ip_channel *channel){
	knx_ip_send_control_rq(channel, KNX_ST::DISCONNECT, "disconnect");
	channel->active=2; // TODO: transform to inactive to make active = false
}

void knx_ip_tun_parse_cemi(const char* frame, size_t sz,
		[[maybe_unused]] void* p_channel){
	char src_addr[10];
	char dst_addr[10];

	// todo: evaluate mc first

	assert(sz >= sizeof(cemi_start));

	const cemi_start* start = (const cemi_start*)frame;
	const cemi_data* data = (const cemi_data*)((char*)frame + sizeof(cemi_start) + start->additional_information_length);

	if(start->message_code != KNX_CEMI_MC::DATA_IND
			&& start->message_code != KNX_CEMI_MC::DATA_REQ ) {
		printf("unknown cemi message code 0x%02x\n", start->message_code);
		return;
	}
	assert(sz >= sizeof(cemi_start) + start->additional_information_length +
		sizeof(cemi_data));
	const uint8_t* tpdu = (const uint8_t*) data + sizeof(cemi_data);

	assert(sz >= sizeof(cemi_start) + start->additional_information_length +
		sizeof(cemi_data) + data->data_length);

	printf("\t\t");
	for(size_t i=0; i < sz; i++) printf("%02x", ((uint8_t*) frame)[i]);
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
	printf("AT: %c, HC: %hd%s\n", data->control_2 & KNX_CTRL2_AT ?'G':'I',
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
void knx_ip_tun_send_cemi(knx_frame_segment* data,
                          knx_ia_t dest, int group, void* p_channel){
    knx_ip_channel *channel = (knx_ip_channel*) p_channel;
#pragma pack(push, 1)
	struct h {
		cemi_start start;
		cemi_data data;
		uint8_t tpci;
	};
#pragma pack(pop)
	h header{
		.start = {
			.message_code = KNX_CEMI_MC::DATA_REQ,
			.additional_information_length = 0,
		},
		.data = {
	        .control_1 = KNX_CTRL1_FT | KNX_CTRL1_R | KNX_CTRL1_SB | KNX_CTRL1_PL,
	        .control_2 = (uint8_t)((group ? KNX_CTRL2_AT : 0) | (6 << KNX_CTRL2_HC_S)),
	        .source_address = channel->ia,
	        .destination_address = htons(dest),
		    .data_length = uint8_t(data->size),
		},
		.tpci = 0x00,
	};
    knx_frame_segment seg_header = {.data = &header,
		.size = sizeof(header), .next = data};

	
	assert(data->size <= std::numeric_limits<uint8_t>::max());

	knx_frame_segment test_frame = knx_frame_assemble(&seg_header);
	knx_ip_tun_parse_cemi((const char*)test_frame.data, test_frame.size, NULL);
	free(test_frame.data);
	knx_ip_tun_send_frame(channel, KNX_ST::TUN, &seg_header);
}


void knx_ip_handler_tunnel(const char* frame, size_t sz, knx_ip_channel* channel) {

	knx_ip_tun_conn_header* chead = (knx_ip_tun_conn_header *)frame;

	assert(sz >= sizeof(knx_ip_tun_conn_header));
	assert(chead->length == sizeof(knx_ip_tun_conn_header));

	knx_ip_tun_parse_cemi(frame + chead->length, sz - chead->length, channel);

	knx_ip_tun_send_ack(channel, chead->seq);
	channel->seq_recv = chead->seq;

	return;
}

void knx_ip_handler_disco(const char* frame, size_t sz, knx_ip_channel* channel){
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
	const f* recv = (const f*)frame;
	fs resp = { .channel = recv->channel, .status = 0x00 }; // FIXME: status
	assert(sz >= sizeof(f));
	assert(recv->channel == channel->channel);

	send(channel->sock, (const char*)& resp, sizeof(resp), 0);

	printf("disconnected\n");

	closesocket(channel->sock);
}

void knx_ip_handler_connres(const char* frame, size_t sz, knx_ip_channel* channel){
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
	const f* b = (const f*)frame;

	assert(channel);
	assert(sz >= sizeof(f));
	assert(!channel->active);
	assert(b->crd.type == 0x04);
	if(b->status != 0x00){
		printf("connection response: FAILED\n");
		return; // not connected properly
	}else printf("connection response\n");

	channel->channel=b->channel;
	channel->ia=b->crd.ia;
	channel->active=1;
	channel->seq_recv = 0;
	channel->seq_send = 0;
}

/* handle connection state response frame */
void knx_ip_handler_csres(const char* frame, size_t sz, knx_ip_channel* channel){
	static int try_=0;
#pragma pack(push, 1)
	struct f {
		uint8_t channel;
		uint8_t status;
	};
#pragma pack(pop)
	const f* b = (const f*)frame;

	assert(sz >= sizeof(f));
	assert(channel->active);
	assert(b->status == 0x00);
	if(b->status != 0x00){
		printf("\tkeepalive FAILED\n");
		if(try_ >= 3)
			knx_ip_send_disconnect(channel);
		else try_++;
		return; // not connected properly
	}else{
		try_ =0;
		printf("\tkeepalive successful\n");
	}
}

