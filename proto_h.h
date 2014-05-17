#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

struct ip_hdr{
	uint8_t ip_vhl;	//ip version + ip header length (in 4 byte word)
	uint8_t ip_tos;	//ip type of service
	uint16_t ip_tl;		//ip total length in bytes
	uint16_t ip_id;	//ip identificatio
	uint16_t ip_ffoffset;	//flag + fragment offset
	#define foffsetmask 0x1fff	// fragment offset mask
	#define IP_DF 0x4000 	// don't fragment flag
	#define IP_MF 0x2000	//May Fragment flag
	uint8_t ip_ttl;	//ip time to live
	uint8_t ip_proto;	//the protocol of the payload of this datagram
	uint16_t ip_sum;	//ip checksum	
	struct  in_addr ip_src,ip_dst;	//the source and destination addresses
}__attribute__((packed));

struct ether_hdr{
	uint8_t ether_dest[ETHER_ADDR_LEN];
	uint8_t ether_src[ETHER_ADDR_LEN];
	uint16_t ether_type;
}__attribute__((packed));

struct tcp_hdr{
	uint16_t tcp_src_port;
	uint16_t tcp_dst_port;
	uint32_t tcp_seq_no;
	uint32_t tcp_ack_no;
	uint8_t tcp_hlen_rsvd;	//4 bits data offset + 4 3 reserved bits
							//offset measures hdr length in 32-bit word
	#define TCP_OFFSET_MASK 0xF1	//this masks the offset AND the NS flag
	uint8_t tcp_flags;
	uint16_t tcp_window;
	uint16_t tcp_sum;
	uint16_t tcp_urg_ptr;
	//options+padding
	//data
}__attribute__((packed));

struct linux_cooked{
	uint16_t lc_packet_type;
	uint16_t lc_ARPHRD_type;
	uint16_t lc_ll_addr_len;
	uint8_t lc_ll_addr[8];
	uint16_t lc_proto_type;	
}__attribute__((packed));
