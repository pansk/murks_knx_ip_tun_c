
#pragma once

#include <cstdint> // uintX_t
#include <WinSock2.h>

#pragma pack(push, 1)

/* selected KNXnet/IP Service Types */
enum class KNX_ST : uint16_t
{
	SEARCH_REQUEST = 0x0201,
	SEARCH = 0x0202,
	CONNREQ = 0x0205,
	CONNRES = 0x0206,
	KEEPALIVE = 0x0207,
	CSRES = 0x0208,
	DISCONNECT = 0x0209,
	DISCONNECT_RET = 0x020a,
	TUN = 0x0420,
	TUN_ACK = 0x0421,
};

struct KNX_ST_NETWORK
{
	uint16_t value_;
	KNX_ST_NETWORK() = default;
	KNX_ST_NETWORK(KNX_ST value) : value_(htons(uint16_t(value))) {}
	//KNX_ST_NETWORK(const KNX_ST_NETWORK&) = default;
	//KNX_ST_NETWORK(KNX_ST_NETWORK&&) = default;
	//KNX_ST_NETWORK& operator = (const KNX_ST_NETWORK&) = default;
	//KNX_ST_NETWORK& operator = (KNX_ST_NETWORK&&) = default;
	//~KNX_ST_NETWORK() = default;

	operator KNX_ST() const {
		return (KNX_ST)ntohs(uint16_t(value_));
	}
};

struct knx_ip_header {
	uint8_t header_length; //0x06
	uint8_t knxip_version; //0x10
	KNX_ST_NETWORK service_type;
	uint16_t length; // including header
};

struct knx_ip_hpai_4 {
	uint8_t length; // 0x08
	uint8_t proto_code; // IPv4 UDP: 0x01, TCP: 0x02
	uint32_t address;
	uint16_t port;
};

struct knx_ip_tun_conn_header {
	uint8_t length; // 0x04
	uint8_t channel;
	uint8_t seq;
	uint8_t resvd;
};
#pragma pack(pop)

typedef uint16_t knx_ia_t;

struct knx_ip_channel {
	SOCKET sock;
	uint8_t channel;
	uint8_t seq_recv;
	uint8_t seq_send;
	knx_ia_t ia;
	int active;
    knx_ip_hpai_4 hpai;
};

struct knx_frame_segment {
	void* data;
	size_t size;
    knx_frame_segment* next;
};

/* all KNX CEMI message codes */
enum class KNX_CEMI_MC : uint8_t
{
	BUSMON_IND = 0x2B,
	DATA_REQ = 0x11,
	DATA_CON = 0x2E,
	DATA_IND = 0x29,
	RAW_REQ = 0x10,
	RAW_CON = 0x2D,
	RAW_IND = 0x2F,
	POLLDATA_REQ = 0x13,
	POLLDATA_CON = 0x25,
	DATACONN_REQ = 0x41,
	DATACONN_IND = 0x89,
	DATAIND_REQ = 0x4A,
	DATAIND_IND = 0x94,
	PROPREAD_REQ = 0xFC,
	PROPREAD_CON = 0xFB,
	PROPWRITE_REQ = 0xF6,
	PROPWRITE_CON = 0xF5,
	PROPINFO_IND = 0xF7,
	FUNCPROPCMD_REQ = 0xF8,
	FUNCPROPSTATEREAD_REQ = 0xF9,
	FUNCPROP_CON = 0xFA, // FuncPropCommand/FuncPropStateread
	RESET_REQ = 0xF1,
	RESET_IND = 0xF0,
};

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

knx_frame_segment knx_frame_assemble(knx_frame_segment* seg);

void knx_ip_send_frame(knx_ip_channel *channel, KNX_ST st,
                       knx_frame_segment* seg);
void knx_ip_send_control_rq(knx_ip_channel *channel, KNX_ST rq,
                            const char* rq_name);
void knx_ip_send_disconnect(knx_ip_channel *channel);

void knx_ip_tun_send_request(knx_ip_channel* channel);
void knx_ip_tun_send_ack(knx_ip_channel *channel, uint8_t seq_nr);
void knx_ip_tun_send_frame(knx_ip_channel *channel, uint16_t st,
                           knx_frame_segment* seg);
void knx_ip_tun_send_cemi(knx_frame_segment* data,
                          knx_ia_t dest, int group, void* p_channel);

void knx_ip_tun_parse_cemi(const char* frame, size_t sz, void* p_channel);

void knx_ip_handler_search(void* frame, size_t sz, void* ret_buf);
void knx_ip_handler_tunnel(const char* frame, size_t sz, knx_ip_channel* p_channel);
void knx_ip_handler_disco(const char* frame, size_t sz, knx_ip_channel* p_channel);
void knx_ip_handler_connres(const char* frame, size_t sz, knx_ip_channel* p_channel);
void knx_ip_handler_csres(const char* frame, size_t sz, knx_ip_channel* p_channel);
