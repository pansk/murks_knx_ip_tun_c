
#pragma once

#include <cstdint> // uintX_t
#include <cstdio>
#include <functional>
#include <map>
#include <vector>
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

struct knx_frame_segment {
	void* data{ nullptr };
	size_t size{ 0 };
	knx_frame_segment* next{ nullptr };
};

enum class connection_status
{
	not_connected = 0,
	connected = 1,
	disconnecting = 2,
	disconnected = 3,
};

struct tgrm_handlers
{
	std::map<KNX_ST, std::vector<std::function<void(const char*, size_t)>>> tgrm_func_handlers_{};

	template<typename FUNC, typename TC>
	void register_handler(KNX_ST type, FUNC&& func) {

		tgrm_func_handlers_[type].push_back([func = std::move(func)](const char* frame, size_t sz)
			{
				func(frame, sz);
			});
	}

	void operator() (KNX_ST type, const char* buf, size_t sz) const {
		const auto handler_element = tgrm_func_handlers_.find(type);
		if (handler_element == tgrm_func_handlers_.end())
		{
			printf("no handler for svc type %04x\n", type);
			return;
		}
		for (auto& f : handler_element->second) {
			f(buf, sz);
		}
	}
};

class knx_ip_channel {

    int try_{ 0 };
    connection_status active_{ connection_status::not_connected };
    void handler_disco(const char* frame, size_t sz);
	void handler_connres(const char* frame, size_t sz);
    void handler_csres(const char* frame, size_t sz);
    void handler_tunnel(const char* frame, size_t sz);

	KNX_ST handle_frame(const char* frame, size_t sz);

	SOCKET sock_{ INVALID_SOCKET };
	uint8_t channel_{};
	uint8_t seq_recv_{ 0 };
	uint8_t seq_send_{ 0 };
	knx_ia_t ia_{};
	knx_ip_hpai_4 hpai_{};

	void send_frame(KNX_ST st, knx_frame_segment* seg) const;

    void tun_send_frame(KNX_ST st, knx_frame_segment* seg);
	void tun_send_ack(uint8_t seq_nr) const;
	void disconnect();
public:
	int connect(const char* host, const char* port);

	void send_control_rq(KNX_ST st) const;
	void send_disconnect();

	void tun_send_request();
	void tun_send_cemi(knx_frame_segment* data, knx_ia_t dest, int group);
    bool receive();
	SOCKET socket() const { return sock_; }
};

/* all KNX CEMI message codes */
enum class KNX_CEMI_MC : uint8_t
{
	RAW_REQ = 0x10,
	DATA_REQ = 0x11,
	POLLDATA_REQ = 0x13,
	POLLDATA_CON = 0x25,
	DATA_IND = 0x29,
	BUSMON_IND = 0x2B,
	RAW_CON = 0x2D,
	DATA_CON = 0x2E,
	RAW_IND = 0x2F,
	DATACONN_REQ = 0x41,
	DATAIND_REQ = 0x4A,
	DATACONN_IND = 0x89,
	DATAIND_IND = 0x94,
	RESET_IND = 0xF0,
	RESET_REQ = 0xF1,
	PROPWRITE_CON = 0xF5,
	PROPWRITE_REQ = 0xF6,
	PROPINFO_IND = 0xF7,
	FUNCPROPCMD_REQ = 0xF8,
	FUNCPROPSTATEREAD_REQ = 0xF9,
	FUNCPROP_CON = 0xFA, // FuncPropCommand/FuncPropStateread
	PROPREAD_CON = 0xFB,
	PROPREAD_REQ = 0xFC,
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

knx_frame_segment knx_frame_assemble(const knx_frame_segment* seg);

void knx_ip_tun_parse_cemi(const char* frame, size_t sz);
