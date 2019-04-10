#include "TCPIP Structures.h"
/*
Ideas:
1. find the avg amount of packets per second
2. if packets per second surpass (100%? 150%? we'll see) check to see if its all under the same port OR same IP addresses
3. if either is true then start saving IP Addresses and recording time, and report ports
*/

void packet_analyzer(u_char * info, const struct pcap_pkthdr * pkthdr, const u_char * packet);
void attack_analysis(information * attack_info, int seconds);
void proccess_packets(ethernet_header * ethernet,ip_header * ip,tcp_header * tcp,udp_header * udp, information * attack_info);
void file_write(information * attack_info);

void attack_analysis(information * attack_info, int seconds){
	cout << attack_info->attk.attackers.size() <<"Ip addresses are being tracked, max is "<< attack_info->attk.attackers.max_size() <<endl;
	//add if statement to say if approaching 80% that limit is approaching and something needs to be done about it (IE start throwing some out)
	int i = 0;
	attack_info->attk.pkts_per_sec = attack_info->attk.processed_pkts-attack_info->attk.old_pkts;
	attack_info->attk.old_pkts = attack_info->attk.processed_pkts;
	for(attack_info->attk.attk_it = attack_info->attk.attackers.begin(); attack_info->attk.attk_it != attack_info->attk.attackers.end(); attack_info->attk.attk_it++, i++){
		attack_info->attk.attackers[i].r_pkt_per_sec = attack_info->attk.attackers[i].recieved_pkts-attack_info->attk.attackers[i].r_old_pkts;
		attack_info->attk.attackers[i].s_pkt_per_sec =  attack_info->attk.attackers[i].sent_pkts-attack_info->attk.attackers[i].s_old_pkts;
		if(attack_info->attk.attackers[i].recieved_pkts/attack_info->attk.attackers[i].sent_pkts >= 1000 || attack_info->attk.attackers[i].r_pkt_per_sec/attack_info->attk.attackers[i].s_pkt_per_sec >=1000){
			if(attack_info->attk.attackers[i].recieved_pkts/attack_info->attk.attackers[i].sent_pkts >= 1000 && attack_info->attk.attackers[i].r_pkt_per_sec/attack_info->attk.attackers[i].s_pkt_per_sec >=1000){
				attack_info->attk.possibility = ATTACK;
			}
			attack_info->attk.possibility = POSSIBLE;
			attack_info->attk.attackers[i].victim = true;
		}
		else if(attack_info->attk.attackers[i].sent_pkts/attack_info->attk.attackers[i].recieved_pkts >= 1000 || attack_info->attk.attackers[i].s_pkt_per_sec/attack_info->attk.attackers[i].r_pkt_per_sec >=1000){
			if(attack_info->attk.attackers[i].sent_pkts/attack_info->attk.attackers[i].recieved_pkts >= 1000 && attack_info->attk.attackers[i].s_pkt_per_sec/attack_info->attk.attackers[i].r_pkt_per_sec >=1000){
				attack_info->attk.possibility = ATTACK;
			}
			attack_info->attk.possibility = POSSIBLE;
			attack_info->attk.attackers[i].attacker = true;
		}
		attack_info->attk.attackers[i].r_old_pkts = attack_info->attk.attackers[i].recieved_pkts;
		attack_info->attk.attackers[i].s_old_pkts = attack_info->attk.attackers[i].sent_pkts;
	}
}
 // CHECK CODE ABOUT PKTS PER SEC BECAUSE I HAVE IT INCREMENTING ON PROCCESS_PACKETS
void file_write(information * attack_info){

}


/*After the packet has been broken up this will take the pieces and insert them to the class information and will analyze
to see if there's an attack happening*/
void proccess_packets(ethernet_header * ethernet,ip_header * ip,tcp_header * tcp,udp_header * udp, information * attack_info){
	attack_info->attk.processed_pkts++;
	
	if (attack_info->attk.attackers.empty()){
		ip_tracker pkt_tkr_src;
		pkt_tkr_src.ip_addr = ip->ip_src;
		pkt_tkr_src.last_used = time(NULL);
		pkt_tkr_src.recieved_pkts++;
		pkt_tkr_src.r_pkt_per_sec++;
		attack_info->attk.attackers.push_back(pkt_tkr_src);

		ip_tracker pkt_tkr_dst;
		pkt_tkr_dst.ip_addr = ip->ip_dst;
		pkt_tkr_dst.last_used = time(NULL);
		pkt_tkr_dst.sent_pkts++;
		pkt_tkr_dst.s_pkt_per_sec++;
		attack_info->attk.attackers.push_back(pkt_tkr_dst);

		}
	else{
		int i = 0;
		bool dst = false;
		bool src = false;
		for(attack_info->attk.attk_it = attack_info->attk.attackers.begin(); attack_info->attk.attk_it != attack_info->attk.attackers.end(); attack_info->attk.attk_it++, i++){
			// if ip.src OR ip.dst is in attackers, 
			//figure out which one, go to attacker[i], reset time used and increment the one needed
			if( ip->ip_src.s_addr == attack_info->attk.attackers[i].ip_addr.s_addr){
				attack_info->attk.attackers[i].last_used = time(NULL);
				attack_info->attk.attackers[i].sent_pkts++;
				attack_info->attk.attackers[i].s_pkt_per_sec++;
				src = true;
			}
			else if( ip->ip_dst.s_addr == attack_info->attk.attackers[i].ip_addr.s_addr){
				attack_info->attk.attackers[i].last_used = time(NULL);
				attack_info->attk.attackers[i].recieved_pkts++;
				attack_info->attk.attackers[i].r_pkt_per_sec++;
				dst = true;
			}
		}
		if (src == false){
			ip_tracker pkt_tkr_src;
			pkt_tkr_src.ip_addr = ip->ip_src;
			pkt_tkr_src.last_used = time(NULL);
			pkt_tkr_src.recieved_pkts++;
			pkt_tkr_src.r_pkt_per_sec++;
			attack_info->attk.attackers.push_back(pkt_tkr_src);
		}
		if (dst == false){
			ip_tracker pkt_tkr_dst;
			pkt_tkr_dst.ip_addr = ip->ip_dst;
			pkt_tkr_dst.last_used = time(NULL);
			pkt_tkr_dst.sent_pkts++;
			pkt_tkr_dst.s_pkt_per_sec++;
			attack_info->attk.attackers.push_back(pkt_tkr_dst);
		}
	}
	if (attack_info->time % CLOCKS_PER_SEC < 10000 && attack_info->time > 10000){
		attack_analysis(attack_info, attack_info->time/CLOCKS_PER_SEC);
		file_write(attack_info);
	}
}

void packet_analyzer(u_char * info, const struct pcap_pkthdr * pkthdr, const u_char * packet) {
	/*Code below until marked was taken from https://www.tcpdump.org/pcap.html, as this is a simple but effective way to grab the information*/
	information * attack_info = reinterpret_cast<information * >(info);
	attack_info->time = clock();
	class ethernet_header * ethernet;
	class ip_header * ip;
	class tcp_header * tcp;
	class udp_header * udp;
	const char * payload;
	u_int size_ip;
	u_int size_tcp;
	u_int size_udp;
	

	ethernet = (class ethernet_header *) (packet);
	ip = (class ip_header *) (packet + SIZE_ETHERNET); // Adding the size of the ethernet layer will move it to the IP 
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		cout << "Invalid IP Header Length: " << size_ip << endl;
		return;
	}
	if ((int)(ip->ip_p) == 0x06) { // TCP Protocol handling and payload
		tcp = (class tcp_header*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TCP_OFF(tcp) * 4;
		if (size_tcp < 20) {
			cout << "Invalid TCP Header Length:" << size_tcp << endl;
			return;
		}
		cout << "Protcol TCP" << endl;
		payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	}
	else if ((int)(ip->ip_p) == 0x11) { // UDP Protocol handling and payload, end code from tcpdump
		udp = (class udp_header*)(packet + SIZE_ETHERNET + size_ip);
		size_udp = udp->udp_len;
		if (size_udp < 8) {
			cout << "Invalid UDP Header Length:" << size_udp << endl;
			return;
		}
		cout << "Protocol UDP" << endl;
		payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
	}
	else {
		cout << "Unsupported Protocol Used, #:" << (int)(ip->ip_p) << endl;
		return;
	}

	proccess_packets(ethernet,ip,tcp,udp,attack_info);

}

int main() {
	char errbuff[PCAP_ERRBUF_SIZE]; //setting the err for it to go to
	pcap_t * a_packets = pcap_open_offline("14_1_0_pcap.pcap", errbuff); //opening the pcap file to be used
	struct bpf_program compiled_filter; //filter 
	class information *info =  new information;
	//info->attk.attackers.resize(10000);

	if (a_packets == NULL) {
		cout << "Error when opening file: " << errbuff << endl;
	}
	//use NULL to pass in variables so that I can bring in time_t to check every second, ip_tracker keep track of the IP's and 
	//a file so i can write to a file every second for the front end
	if (pcap_loop(a_packets, 0 ,packet_analyzer, reinterpret_cast<u_char*>(info)) < 0) {
		cout << "Error while looping:" << pcap_geterr(a_packets) << endl;
	}
	return 0;
}




