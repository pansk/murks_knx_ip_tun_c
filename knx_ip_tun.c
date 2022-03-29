#include"knx_ip_tun.h"
#include<stdio.h>
#include<stdlib.h> // malloc/free
#include<unistd.h> // close
#include<arpa/inet.h> // send
#include<string.h> // memcpy
#include<assert.h>
#include<endian.h> // htobe16

char knx_print_prio_char(uint8_t c1){
	uint8_t p = c1 & KNX_CTRL1_PRIO;
	return (p == KNX_CTRL1_PL)?'L':(
			(p == KNX_CTRL1_PN)?'N':(
				(p == KNX_CTRL1_PU)?'U':'S'));
}
char* knx_print_ia(knx_ia_t na, char* s){
	uint16_t a = be16toh(na);
	snprintf(s, 10, "%hd.%hd.%hd", (a & 0xf000) >> 12,
		(a & 0x0f00) >> 8, (a & 0x00ff));
	return s;
}
char* knx_print_ga(knx_ia_t na, char* s){
	uint16_t a = be16toh(na);
	snprintf(s, 10, "%hd/%hd/%hd", (a & 0xf000) >> 12,
		(a & 0x0f00) >> 8, (a & 0x00ff));
	return s;
}

void knx_ip_tun_send_request(struct knx_ip_channel* channel){
	struct __attribute__((packed)) cri { /* connect request information */
		uint8_t length;
		uint8_t type;
		uint8_t layer;
		uint8_t resvd;
	//	hostproto_indep_data;
	//	hostproto_dep_data;
	} cri;

	struct knx_frame_segment s_cri = { .data = &cri, sizeof(struct cri),
		.next = NULL }; /* last segment */
	struct knx_frame_segment s_data = { .data = &channel->hpai,
		sizeof(struct knx_ip_hpai_4), .next = &s_cri }; /* second segement */
	struct knx_frame_segment s_ctrl = { .data = &channel->hpai,
		sizeof(struct knx_ip_hpai_4), .next = &s_data }; /* first segment */

	assert(channel->hpai.length == sizeof(struct knx_ip_hpai_4));

	cri.length = sizeof(struct cri); // 0x04
	cri.type = 0x04; // TUNNEL_CONNECTION = 0x04
	cri.layer = 0x02; // TUNNEL_LINKLAYER = 0x02
	cri.resvd = 0x00;; // 0x00

	knx_ip_send_frame(channel, KNX_ST_CONNREQ, &s_ctrl);
}


void knx_ip_tun_send_ack(struct knx_ip_channel *channel, uint8_t seq_nr){
	 struct __attribute__((packed)) f {
		struct knx_ip_header knx_ip_header;
		struct knx_ip_tun_conn_header ch;
	} b;

	b.knx_ip_header.header_length = sizeof(struct knx_ip_header); //0x06
	b.knx_ip_header.knxip_version = 0x10;
	b.knx_ip_header.service_type = htobe16(KNX_ST_TUN_ACK); // tun ack
	b.knx_ip_header.length = htobe16(sizeof(struct f));

	b.ch.length = sizeof(struct knx_ip_tun_conn_header); // 0x04
	b.ch.channel = channel->channel;
	b.ch.seq = seq_nr;
	b.ch.resvd = 0x00;

	send(channel->sock, &b, sizeof(b), 0);
	printf("\tframe acked\n");
}

void knx_ip_send_control_rq(struct knx_ip_channel *channel, uint16_t rq,
		const char* rq_name){
	 struct __attribute__((packed)) f {
		struct knx_ip_header knx_ip_header;
		uint8_t channel;
		uint8_t resvd;
		struct knx_ip_hpai_4 hpai;
	} b;

	b.knx_ip_header.header_length = sizeof(struct knx_ip_header); //0x06
	b.knx_ip_header.knxip_version = 0x10;
	b.knx_ip_header.service_type = htobe16(rq);
	b.knx_ip_header.length = htobe16(sizeof(struct f));

	// control endpoint
	b.channel = channel->channel;
	b.resvd = 0x00;
	assert(channel->hpai.length == sizeof(struct knx_ip_hpai_4));
	memcpy(&b.hpai, &channel->hpai, sizeof(struct knx_ip_hpai_4));

	send(channel->sock, &b, sizeof(b), 0);
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
struct knx_frame_segment knx_frame_assemble(struct knx_frame_segment* seg){
	struct knx_frame_segment* s;
	struct knx_frame_segment r = { .data = NULL, .size = 0, .next = NULL };
	size_t offset = 0;

	for(s = seg; s != NULL; s = s->next) r.size += s->size;
	r.data = malloc(r.size);
	for(s = seg; s != NULL; s = s->next) {
		memcpy(r.data + offset, s->data, s->size);
		offset += s->size;
	}
	return r;
}

void knx_ip_send_frame(struct knx_ip_channel *channel, uint16_t st,
		struct knx_frame_segment* seg){
	struct knx_ip_header knx_ip_header, *frame_knx_ip_header;
	struct knx_frame_segment frame;
	struct knx_frame_segment hs = {.data = &knx_ip_header,
		.size = sizeof(struct knx_ip_header), .next = seg};

	knx_ip_header.header_length = sizeof(struct knx_ip_header); //0x06
	knx_ip_header.knxip_version = 0x10;
	knx_ip_header.service_type = htobe16(st);
	knx_ip_header.length = 0; // ensure all memory is zeroed
	/* knx_ip_header.length can not be set here, because final overall frame
	 * size is not known yet. */

	frame = knx_frame_assemble(&hs);
	/* map start of final frame data to knx ip header, to be able to set
	 * overall frame length */
	frame_knx_ip_header = frame.data;
	frame_knx_ip_header->length = htobe16(frame.size);

	send(channel->sock, frame.data, frame.size, 0);
	printf("frame sent\n");
	free(frame.data);
}

void knx_ip_tun_send_frame(struct knx_ip_channel *channel, uint16_t st,
		struct knx_frame_segment* seg){
	struct knx_ip_tun_conn_header ch;

	struct knx_frame_segment ch_s = {.data = &ch,
		.size = sizeof(struct knx_ip_tun_conn_header), .next = seg};

	ch.length = sizeof(struct knx_ip_tun_conn_header); // 0x04
	ch.channel = channel->channel;
	ch.seq = channel->seq_send;
	ch.resvd = 0x00;

	knx_ip_send_frame(channel, st, &ch_s);
	channel->seq_send++;
}

void knx_ip_send_disconnect(struct knx_ip_channel *channel){
	knx_ip_send_control_rq(channel, 0x0209, "disconnect");
	channel->active=2; // TODO: transform to inactive to make active = false
}

void knx_ip_tun_parse_cemi(void* frame, size_t sz,
		__attribute__((unused))void* p_channel){
	size_t i;
	struct __attribute__((packed)) cemi_start {
		uint8_t mc; // message code
		uint8_t addil; // addditional information length
	}  *cemi_start;
	struct __attribute__((packed)) cemi_data {
		uint8_t c1;
		uint8_t c2;
		knx_ia_t sa;
		knx_ia_t da;
		uint8_t npdu_length;
	} *cemi_data;
	uint8_t *tpdu;
	char src_addr[10];
	char dst_addr[10];

	// todo: evaluate mc first

	assert(sz >= sizeof(struct cemi_start));

	cemi_start = frame;
	cemi_data = frame + sizeof(struct cemi_start) + cemi_start->addil;

	if(cemi_start->mc != KNX_CEMI_MC_DATA_IND
			&& cemi_start->mc != KNX_CEMI_MC_DATA_REQ ) {
		printf("unknown cemi message code 0x%02x\n", cemi_start->mc);
		return;
	}
	assert(sz >= sizeof(struct cemi_start) + cemi_start->addil +
		sizeof(struct cemi_data));
	tpdu = (void*) cemi_data + sizeof(struct cemi_data);

	assert(sz >= sizeof(struct cemi_start) + cemi_start->addil +
		sizeof(struct cemi_data) + cemi_data->npdu_length);

	printf("\t\t");
	for(i=0; i < sz; i++) printf("%02x", ((uint8_t*) frame)[i]);
	printf("\n");

	printf("\tmc: 0x%02x, npdu length: 0x%02x (+1 +0x%02x addil), tpci %02x\n",
		cemi_start->mc, cemi_data->npdu_length, cemi_start->addil,
		tpdu[0]);
	printf("\tFT: %c rpt: %c bcst: %c prio: %c ack: %c cf: %c ",
		cemi_data->c1 & KNX_CTRL1_FT ?'S':'E', // standard frame
		(cemi_data->c1 & KNX_CTRL1_R)?'N':'T', // Repeat
		(cemi_data->c1 & KNX_CTRL1_SB)?'D':'S',
		knx_print_prio_char(cemi_data->c1),
		(cemi_data->c1 & KNX_CTRL1_A)?'T':'N',
		(cemi_data->c1 & KNX_CTRL1_C)?'T':'N');
	printf("AT: %c, HC: %hd%s\n", cemi_data->c2 & KNX_CTRL2_AT ?'G':'I',
		(cemi_data->c2 & KNX_CTRL2_HC) >> KNX_CTRL2_HC_S,
		(cemi_data->c2 & KNX_CTRL2_EFF) ? ", EFF":"");
	printf("\t%s -> %s\n", knx_print_ia(cemi_data->sa, src_addr),
		(cemi_data->c2 & KNX_CTRL2_AT)
		?  knx_print_ga(cemi_data->da, dst_addr)
		: knx_print_ia(cemi_data->da, dst_addr));

	printf("\tdata: ");
	for(i=0; i < cemi_data->npdu_length; i++)
		printf("%02x", tpdu[i+1]);
	printf("\n");
}

/* send CEMI frame to tunnel endpoint
 * send `data` to `dest`. `dest` is group address if `group` true */
void knx_ip_tun_send_cemi(struct knx_frame_segment* data,
		knx_ia_t dest, int group, void* p_channel){
	struct knx_frame_segment test_frame;
	struct knx_ip_channel *channel = (struct knx_ip_channel*) p_channel;
	static struct __attribute__((packed)) h{
		uint8_t mc; // message code
		uint8_t addil; // addditional information length = 0
		uint8_t c1;
		uint8_t c2;
		knx_ia_t sa;
		knx_ia_t da;
		uint8_t npdu_length;
		uint8_t tpci;
	} h;
	struct knx_frame_segment seg_header = {.data = &h,
		.size = sizeof(struct h), .next = data};

	h.mc = KNX_CEMI_MC_DATA_REQ;
	h.addil = 0;
	h.c1 = KNX_CTRL1_FT | KNX_CTRL1_R | KNX_CTRL1_SB | KNX_CTRL1_PL;
	h.c2 = (group ? KNX_CTRL2_AT : 0) | (6 << KNX_CTRL2_HC_S);
	h.sa = channel->ia;
	h.da = htobe16(dest);
	h.npdu_length = data->size;
	h.tpci = 0x00;

	test_frame = knx_frame_assemble(&seg_header);
	knx_ip_tun_parse_cemi(test_frame.data, test_frame.size, NULL);
	free(test_frame.data);
	knx_ip_tun_send_frame(channel, KNX_ST_TUN, &seg_header);
}


void knx_ip_handler_tunnel(void* frame, size_t sz, void* p_channel){
	struct knx_ip_channel *channel = (struct knx_ip_channel*) p_channel;

	struct knx_ip_tun_conn_header *chead = frame;

	assert(sz >= sizeof(struct knx_ip_tun_conn_header));
	assert(chead->length == sizeof(struct knx_ip_tun_conn_header));

	knx_ip_tun_parse_cemi(frame + chead->length, sz - chead->length, p_channel);

	knx_ip_tun_send_ack(channel, chead->seq);
	channel->seq_recv = chead->seq;

	return;
}

void knx_ip_handler_disco(void* frame, size_t sz, void* p_channel){
	const struct knx_ip_channel channel = *((struct knx_ip_channel*) p_channel);
	struct __attribute__((packed)) f {
		uint8_t channel;
		uint8_t resvd;
		struct knx_ip_hpai_4 hpai;
	} *recv = frame;

	struct __attribute__((packed)) fs {
		uint8_t channel;
		uint8_t status;
	} resp = {.channel = recv->channel, .status = 0x00 }; // FIXME: status

	assert(sz >= sizeof(struct f));
	assert(recv->channel == channel.channel);

	send(channel.sock, &resp, sizeof(resp), 0);

	printf("disconnected\n");

	close(channel.sock);
}

void knx_ip_handler_connres(void* frame, size_t sz, void* p_channel){
	struct __attribute__((packed)) f {
		uint8_t channel;
		uint8_t status;
		struct knx_ip_hpai_4 hpai;
		struct __attribute__((packed)) knx_ip_crd {
			uint8_t length;
			uint8_t type;
			knx_ia_t ia; // FIXME: Union/Typedef knx_ia_t
		} crd;
	} *b=frame;
	struct knx_ip_channel *channel=p_channel;

	assert(p_channel);
	assert(sz >= sizeof(struct f));
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
void knx_ip_handler_csres(void* frame, size_t sz, void* p_channel){
	static int try=0;
	struct __attribute__((packed)) f {
		uint8_t channel;
		uint8_t status;
	} *b=frame;
	struct knx_ip_channel *channel=p_channel;

	assert(sz >= sizeof(struct f));
	assert(channel->active);
	assert(b->status == 0x00);
	if(b->status != 0x00){
		printf("\tkeepalive FAILED\n");
		if(try >= 3)
			knx_ip_send_disconnect(channel);
		else try++;
		return; // not connected properly
	}else{
		try=0;
		printf("\tkeepalive successful\n");
	}
}

