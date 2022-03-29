#include<stdint.h> // uintX_t
#include<sys/types.h> // size_t

struct __attribute__((packed)) knx_ip_header {
	uint8_t header_length; //0x06
	uint8_t knxip_version; //0x10
	uint16_t service_type;
	uint16_t length; // including header
};

struct __attribute__((packed)) knx_ip_hpai_4 {
	uint8_t length; // 0x08
	uint8_t proto_code; // IPv4 UDP: 0x01, TCP: 0x02
	uint32_t address;
	uint16_t port;
};

struct __attribute__((packed)) knx_ip_tun_conn_header {
	uint8_t length; // 0x04
	uint8_t channel;
	uint8_t seq;
	uint8_t resvd;
};

typedef uint16_t knx_ia_t;

struct knx_ip_channel {
	int sock;
	uint16_t channel;
	uint16_t seq_recv;
	uint16_t seq_send;
	knx_ia_t ia;
	int active;
	struct knx_ip_hpai_4 hpai;
};

struct knx_frame_segment {
	void* data;
	size_t size;
	struct knx_frame_segment* next;
};


/* selected KNXnet/IP Service Types */
#define KNX_ST_CONNREQ 0x0205
#define KNX_ST_CONNRES 0x0206
#define KNX_ST_DISCO 0x0209
#define KNX_ST_DISCO_RET 0x020a
#define KNX_ST_CSRES 0x0208
#define KNX_ST_SEARCH 0x0202
#define KNX_ST_TUN 0x0420
#define KNX_ST_TUN_ACK 0x0421

/* all KNX CEMI message codes */
#define KNX_CEMI_MC_BUSMON_IND 0x2B
#define KNX_CEMI_MC_DATA_REQ 0x11
#define KNX_CEMI_MC_DATA_CON 0x2E
#define KNX_CEMI_MC_DATA_IND 0x29
#define KNX_CEMI_MC_RAW_REQ 0x10
#define KNX_CEMI_MC_RAW_CON 0x2D
#define KNX_CEMI_MC_RAW_IND 0x2F
#define KNX_CEMI_MC_POLLDATA_REQ 0x13
#define KNX_CEMI_MC_POLLDATA_CON 0x25
#define KNX_CEMI_MC_DATACONN_REQ 0x41
#define KNX_CEMI_MC_DATACONN_IND 0x89
#define KNX_CEMI_MC_DATAIND_REQ 0x4A
#define KNX_CEMI_MC_DATAIND_IND 0x94
#define KNX_CEMI_MC_PROPREAD_REQ 0xFC
#define KNX_CEMI_MC_PROPREAD_CON 0xFB
#define KNX_CEMI_MC_PROPWRITE_REQ 0xF6
#define KNX_CEMI_MC_PROPWRITE_CON 0xF5
#define KNX_CEMI_MC_PROPINFO_IND 0xF7
#define KNX_CEMI_MC_FUNCPROPCMD_REQ 0xF8
#define KNX_CEMI_MC_FUNCPROPSTATEREAD_REQ 0xF9
#define KNX_CEMI_MC_FUNCPROP_CON 0xFA // FuncPropCommand/FuncPropStateread
#define KNX_CEMI_MC_RESET_REQ 0xF1
#define KNX_CEMI_MC_RESET_IND 0xF0

#define KNX_CTRL1_FT (1<<7) // Frame Type (standard)
#define KNX_CTRL1_R (1<<5) // Repeat (No)
#define KNX_CTRL1_SB (1<<4) // Broadcast (Domain = Not system)
#define KNX_CTRL1_PRIO (1<<3 | 1<<2)
#define KNX_CTRL1_PL (1<<3 | 1<<2) // Prio low
#define KNX_CTRL1_PN (1<<2) // Prio normal
#define KNX_CTRL1_PU (1<<3) // Prio urgent
#define KNX_CTRL1_PS 0 // Prio system
#define KNX_CTRL1_A (1<<1) // L2ACK (request)
#define KNX_CTRL1_C (1<<0) // Confirm (error)

#define KNX_CTRL2_AT (1<<7) // Address Type (Group)
#define KNX_CTRL2_HC (1<<6 | 1<<5 | 1<<4) // Hop Count
#define KNX_CTRL2_HC_S 4
#define KNX_CTRL2_EFF 1<<2

struct knx_frame_segment knx_frame_assemble(struct knx_frame_segment* seg);

void knx_ip_send_frame(struct knx_ip_channel *channel, uint16_t st,
		struct knx_frame_segment* seg);
void knx_ip_send_control_rq(struct knx_ip_channel *channel, uint16_t rq,
		const char* rq_name);
void knx_ip_send_disconnect(struct knx_ip_channel *channel);

void knx_ip_tun_send_request(struct knx_ip_channel* channel);
void knx_ip_tun_send_ack(struct knx_ip_channel *channel, uint8_t seq_nr);
void knx_ip_tun_send_frame(struct knx_ip_channel *channel, uint16_t st,
		struct knx_frame_segment* seg);
void knx_ip_tun_send_cemi(struct knx_frame_segment* data,
		knx_ia_t dest, int group, void* p_channel);

void knx_ip_tun_parse_cemi(void* frame, size_t sz, void* p_channel);

void knx_ip_handler_search(void* frame, size_t sz, void* ret_buf);
void knx_ip_handler_tunnel(void* frame, size_t sz, void* p_channel);
void knx_ip_handler_disco(void* frame, size_t sz, void* p_channel);
void knx_ip_handler_connres(void* frame, size_t sz, void* p_channel);
void knx_ip_handler_csres(void* frame, size_t sz, void* p_channel);
