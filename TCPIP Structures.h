#pragma once
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iomanip> 
#include <iterator>
#include <iostream>
#include <fstream>
#include <vector>
#include <pcap.h>
#include <string>
#include <time.h>
#include <math.h>
using namespace std;

/*the headers below were found in https://www.tcpdump.org/pcap.html, was modified a bit for easier understanding */

/* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14
/* Ethernet header */
class ethernet_header {
public:
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */	
};

/* IP header */
class ip_header {
public:
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int th_seq;

class tcp_header {
public:
	u_short tcp_sport;	/* source port */
	u_short tcp_dport;	/* destination port */
	th_seq tcp_seq;		/* sequence number */
	th_seq tcp_ack;		/* acknowledgement number */
	u_char tcp_offx2;	/* data offset, rsvd */
#define TCP_OFF(tcp)	(((tcp)->tcp_offx2 & 0xf0) >> 4)
	u_char tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_PSH|TCP_ACK|TCP_URG|TCP_ECE|TCP_CWR)
	u_short tcp_win;		/* window */
	u_short tcp_sum;		/* checksum */
	u_short tcp_urp;		/* urgent pointer */
};
/*End copy*/
/* UDP header */

class udp_header {
	public:
		u_short udp_sport;  /* source port */
		u_short udp_dport;  /* destination port */
		u_short udp_len;    /* length */
		u_short udp_sum;    /* checksum */
};

enum conf_of_attack{
	NONE = 0, // neither received pkts or r pkt per sec has an extreme amounnt above sent/sent per sec
	POSSIBLE = 1, // received/sent has an extreme amount above sent/received but not r/s_per_sec, or visa versa
	ATTACK = 2, //both ratio
};

class ip_tracker {
	public:
		struct in_addr ip_addr;
		time_t last_used;
		int recieved_pkts = 0, sent_pkts = 0, r_pkt_per_sec = 0, s_pkt_per_sec = 0, r_old_pkts = 0, s_old_pkts = 0;
		 // r and s pkt_per_sec means how many were sent/recived this second, not the avg every second
		bool attacker = false;
		bool victim = false;
};

class attack{
	public:
		ofstream file;
		int time;
		 vector<ip_tracker> attackers;
		 vector<ip_tracker>::iterator attk_it;
		int pkts_per_sec, processed_pkts = 0,old_pkts = 0;
		int start_time,end_time;
		conf_of_attack possibility;
};

class information{
	public:
		attack attk;
		clock_t time;
};

