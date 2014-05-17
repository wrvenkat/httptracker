#include "proto_h.h"
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <stdlib.h>
#include <string.h>

#define OPT_STRING "-m-v-s-d-l-a-h-n:-i:"
#define SNAP_LEN 1518
#define PCAP_FILTER "tcp port 80 || tcp port 8080"
#define PROMISC 1
#define INTF_ALL "any"

struct args{
	int debug_mode;
	int verbose;
	int print_src_ip;
	int link_type;
};

void usage();

//void description();

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void list_interfaces();

void http_tracker(int debug_mode,int exclude_own,int verbose,int print_src_ip,int excl_loopback,int exit_count,char * intf);

void get_interface_addresses(char *intf,char intf_addresses[][26]);

char* packet_to_a(unsigned char*,int);

float timeval_to_sec(struct timeval);

int main(int argc, char ** argv){
	/*s
	 
	 sdfsssssssssss */
	//initialized with default values
	int exclude_own = 0;
	int verbose = 0;
	int print_src_ip = 0;
	int debug_mode=0;
	int excl_loopback=0;
	int help=0;
	int list_intf=0;
	int exit_count=0;	
	char *intf=0;	
	char opt=0;
	
	//get the options provided
	opt=getopt(argc,argv,OPT_STRING);
	while(opt!=-1){
		switch (opt) {
			case 'm':
				exclude_own=1;
				break;
			case 'v':
				verbose=1;
				break;
			case 's':
				print_src_ip=1;
				break;
			case 'd':
				debug_mode=1;
				break;
			case 'l':
				excl_loopback=1;
				break;
			case 'h':
				help=1;
				break;
			case 'a':
				list_intf=1;
				break;
			case 'n':
				exit_count=optarg;
				if(!exit_count)
					usage();
				else
					exit_count=(int)*optarg;
				break;
			case 'i':
				intf=optarg;
				if(!intf)
					usage();
				break;
			case '?':
				usage();
				break;
			default:
				usage();
				break;
		}
		opt=getopt(argc,argv,OPT_STRING);
	}
	
	//check for help flag
	if(help) usage();
	
	//if the list interfaces was specified
	if(list_intf)	list_interfaces();
	
	//start the filtering
	http_tracker(debug_mode,exclude_own,verbose,print_src_ip,excl_loopback,exit_count,intf);
	
	return(0);
}

// this function displays the usage of the program
void usage(){
	fprintf(stdout,"Usage: ./httptracker -m -v -s -h -a -d -l -n count -i intf_name\n");
	fprintf(stdout,"-m - exclude packets from your machine on the interface(s) specified\n");
	fprintf(stdout,"-v - verbose output (print all of application layer data)\n");
	fprintf(stdout,"-s - print src IP address of packets\n");
	fprintf(stdout,"-l - exclude any loopback interface when sniffing on all intefaces\n");
	fprintf(stdout,"-h - print this help message and exit\n");
	fprintf(stdout,"-a - list all intetrfaces available that this program can capture on and exit(depends on user privileges)\n");
	fprintf(stdout,"-d - print debug messages\n");
	fprintf(stdout,"-n count - number of packets to capture before quitting (-1 (default) equals infinity)\n");
	fprintf(stdout,"-i intf_name - capture HTTP traffic on the intf_name interface\n");
	exit(0);
}

//this function returns the time in seconds from
//a struct timeval
float timeval_to_sec(struct timeval time){
	return time.tv_sec+(time.tv_usec/1000000);
}

//prints padding spaces
void print_padding_spaces(int max_len,int str_len){
	int k=0;
	while(k<(max_len-str_len)){
		printf(" ");
		k++;
	}
}

//this function is responsible for makng sense of the capture and
//printing relevant matter to the user
void process_packet(u_char *arguments,const struct pcap_pkthdr *header,const u_char *packet){	
	u_char *app_layer=0;
	uint8_t data_len=0;
	struct tcp_hdr *trans_layer=0;
	uint8_t trans_layer_length=0;
	uint8_t trans_hdr_length=0;
	struct ip_hdr *ip_layer=0;
	uint8_t ip_layer_length=0;	
	uint8_t ip_hdr_length=0;
	char src_port[6];
	char dst_port[6];
	memset(src_port,0,6);
	memset(dst_port,0,6);
	
	//print the time it was sniffed
	//printf("%5.3f",timeval_to_sec(header->ts));
	//make sense of the arguments, importantly of the link type packet
	//this means an ethernet encapsulation IEEE 802.3	
	if(((struct args*)arguments)->link_type==DLT_EN10MB){
		/*if(((struct args*)arguments)->debug_mode)
			printf("Link Type: IEEE 802.3 Ethernet\n");*/
		printf("%s  ",packet_to_a(((struct ether_hdr *)packet)->ether_src,ETHER_ADDR_LEN));
		ip_layer=(struct ip_hdr*)(packet+sizeof(struct ether_hdr));		
	}
	else if(((struct args*)arguments)->link_type==DLT_LINUX_SLL){
		/*if(((struct args*)arguments)->debug_mode)
			printf("Link Type: Linux CookedUp\n");*/
		printf("%s  ",packet_to_a(((struct linux_cooked *)packet)->lc_ll_addr,
								    ntohs(((struct linux_cooked *)packet)->lc_ll_addr_len)));
		ip_layer=(struct ip_hdr*)(packet+sizeof(struct linux_cooked));
	}
	else{
		printf("Someother link layer encapsulation\n");
		return;
	}
	ip_layer_length=ntohs(ip_layer->ip_tl);
	ip_hdr_length=(uint8_t)(ip_layer->ip_vhl & 0x0F)*4;
	//this means we gotta print the src IP
	if(((struct args*)arguments)->print_src_ip)
		printf("%s",inet_ntoa(ip_layer->ip_src));
	//print padding spaces
	print_padding_spaces(15,strlen(inet_ntoa(ip_layer->ip_src)));
	printf(" ");
	trans_layer=(struct tcp_hdr *)((uint8_t *)ip_layer+ip_hdr_length);	
	trans_hdr_length=(uint8_t)((trans_layer->tcp_hlen_rsvd & 0xF0) >> 4)*4;
	trans_layer_length=ip_layer_length-ip_hdr_length;	
	app_layer=(u_char*)((uint8_t *)trans_layer+trans_hdr_length);
	data_len=ip_layer_length-(ip_hdr_length+trans_hdr_length);
	sprintf(src_port,"%d",ntohs(trans_layer->tcp_src_port));
	printf(" %d",ntohs(trans_layer->tcp_src_port));	
	print_padding_spaces(5,strlen(src_port));
	sprintf(dst_port,"%d",ntohs(trans_layer->tcp_dst_port));
	printf(" %d",ntohs(trans_layer->tcp_dst_port));	
	print_padding_spaces(5,strlen(dst_port));
	/*if(((struct args*)arguments)->debug_mode){
		printf("IPTotalLength:%d ",ip_layer_length);
		printf("IPHeaderLength:%d ",ip_hdr_length);
		printf("TCPTotalLength:%d ",trans_layer_length);
		printf("TCPHeaderLength:%d ",trans_hdr_length);
		printf("DataLength:%d ",data_len);
	}*/
	char *host_ptr=0;
	host_ptr=strstr((char *)app_layer,"Host:");
	if(host_ptr){
		int i=0;
		printf(" ");
		while(*(host_ptr+i)!='\n')
			printf("%c",*(host_ptr+i++));
	}
	//printf(" %c",*(app_layer));
	
	printf("\n");
}

//the function that performs the actual capture by setting the device, 
//opening the device, applying the filter, and calling the function required
//for each packet
void http_tracker(int debug_mode,int exclude_own, int verbose, int print_src_ip,int excl_loopback,int exit_count,char * intf){
	if(debug_mode)
		fprintf(stdout,"Options Set:\nInclude own IP address (-m): %d\nVerbose (-v): %d\nPrint Source IP (-s): %d\nInterface (-i): %s\n",
			    exclude_own,verbose,print_src_ip,intf);
	char filter_expression[4096];
	struct bpf_program fp;			/* compiled filter program (expression) */
	memset(filter_expression,0,4096);
	char *filter_expression_ptr=filter_expression;
	//alter the filter expression
	strcpy(filter_expression_ptr,PCAP_FILTER);
	filter_expression_ptr+=strlen(PCAP_FILTER);
			    
	//make sense of the various options provided		    
	//set the interface we need to sniff on
	if(!intf)	intf=INTF_ALL;
	//if we need to exclude packets from one or more of our interfaces
	if(exclude_own){
		//find the interfaces and get the IP addresses to ignore
		char intf_addresses[5][26];
		int i=0;
		while(i<5)
			memset(intf_addresses[i++],0,26);
		get_interface_addresses(intf,intf_addresses);		
		
		i=0;		
		//now the rest of the MAC addresses
		while(i<5 && intf_addresses[i][0]!=0){
			sprintf(filter_expression_ptr," && ether host! %s",intf_addresses[i]);
			filter_expression_ptr+=strlen(" && ether host! ")+strlen(intf_addresses[i]);
			i++;
		}				
	}
	//we need to exclude loopback addresses
	if(excl_loopback){
		if(!exclude_own){
			char intf_addresses[1][26];
			memset(intf_addresses[0],0,26);
			get_interface_addresses("lo",intf_addresses);
			if(strlen(intf_addresses[0])!=0)
				sprintf(filter_expression_ptr," && ether host! %s",intf_addresses[0]);
		}
	}
	
	if(debug_mode)	printf("The Filter Expression is %s\n",filter_expression);
	
	//open the device for sniffing
	pcap_t *handle=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	handle = pcap_open_live(intf,SNAP_LEN,PROMISC,1000,errbuf);
	if(handle==NULL){
		fprintf(stderr,"Couldn't open device %s\n",errbuf);
		if(debug_mode)
			fprintf(stdout,"Couldn't open device %s\n",errbuf);
		exit(1);
	}
	
	//check for any warning messages in errbuf
	if(errbuf[1]!=0)
		fprintf(stdout,"WARNING: %s",errbuf);
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	
	bpf_u_int32 netip;	//IPv4 address
	bpf_u_int32 maskp;	//Net mask
	
	//get the IPv4 address and netmask of the device provided
	if(pcap_lookupnet(intf,&netip,&maskp,errbuf)==-1){
		fprintf(stderr,"Couldn't get netmask for device %s: %s\n", intf, errbuf);
		if(debug_mode)
			fprintf(stdout,"Couldn't get netmask for device %s: %s\n", intf, errbuf);
		exit(1);
	}
	
	//compile the filter expression
	if (pcap_compile(handle, &fp, filter_expression, 0, maskp) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expression, pcap_geterr(handle));
		exit(1);
	}
	
	//apply the compiled filter
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",filter_expression, pcap_geterr(handle));
		exit(1);
	}
	
	struct args arguments;
	arguments.debug_mode=debug_mode;
	arguments.verbose=verbose;
	arguments.print_src_ip=print_src_ip;
	arguments.link_type=pcap_datalink(handle);	
	
	//set the callback function
	if(exit_count)
		pcap_loop(handle,exit_count,process_packet,(u_char*)&arguments);
	else
		pcap_loop(handle,-1,process_packet,(u_char*)&arguments);
		
	//closing cleanup
	pcap_freecode(&fp);
	pcap_close(handle);
}

//this function gets the addresses of the interface provided
void get_interface_addresses(char * intf,char intf_addresses[][26]){	
	//this means we need to get all the possible addresses possible
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(pcap_findalldevs(&alldevs,errbuf)==-1){
		fprintf(stdout,"Unable to look up interfaces: %s",errbuf);
		exit(1);
	}
	int i=0;
	pcap_if_t *temp_dev=0;
	for(temp_dev=alldevs;temp_dev!=NULL;){
		if(strcmp(intf,INTF_ALL)){
			if(strcmp(intf,temp_dev->name)){
				temp_dev=temp_dev->next;
				continue;
			}				
		}
		if(temp_dev->addresses){
			pcap_addr_t *temp_pcap_addr=temp_dev->addresses;
			//get all possible physical addresses for this device
			while(temp_pcap_addr){
				if(temp_pcap_addr->addr && temp_pcap_addr->addr->sa_family==AF_PACKET){
					strcpy(intf_addresses[i++],packet_to_a(((struct sockaddr_ll *)temp_pcap_addr->addr)->sll_addr,
														 ((struct sockaddr_ll *)temp_pcap_addr->addr)->sll_halen));
				}
				temp_pcap_addr=temp_pcap_addr->next;
			}
		}
		temp_dev=temp_dev->next;
	}	
	pcap_freealldevs(alldevs);
}

//this function converts a given sa_data member to
//readable MAC address format
char* packet_to_a(unsigned char * sa_data, int length){
	static char mac_address[25];	//xx:xx:xx:xx:xx:xx/0
	memset(mac_address,0,25);	
	int i=0;
	int j=0;
	while(i<length){
		sprintf(mac_address+(j++),"%x",((uint8_t)sa_data[i] & 0xF0) >>4);
		sprintf(mac_address+(j++),"%x",((uint8_t)sa_data[i]) & 0x0F);
		if(i!=length-1)
			sprintf(mac_address+(j++),":");
		i++;	
	}
	return mac_address;
}

//this function lists all the interfaces that this program can capture
//on (depends in privileges)
void list_interfaces(){
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(pcap_findalldevs(&alldevs,errbuf)==-1){
		fprintf(stdout,"Unable to look up interfaces: %s",errbuf);
		exit(1);
	}
	
	//print the details for each interface/device
	pcap_if_t *temp_dev=0;
	for(temp_dev=alldevs;temp_dev!=NULL;temp_dev=temp_dev->next){
		printf("Name: %s",temp_dev->name);
		if(temp_dev->description)
			printf("\n\tDescription: %s",temp_dev->description);
		if(temp_dev->addresses){
			pcap_addr_t *temp_pcap_addr=temp_dev->addresses;			
			while(temp_pcap_addr){				
				if(temp_pcap_addr->addr){					
					int address_family=temp_pcap_addr->addr->sa_family;
					if(address_family==AF_INET){		//IPv4 address family
						printf("\n\tAddress Family: IPv4\n");										
						printf("\tIPv4 Address: %s",inet_ntoa(((struct sockaddr_in*)temp_pcap_addr->addr)->sin_addr));
					}
					else if(address_family==AF_PACKET){
						printf("\n\tAddress Family: Raw Packet (AF_PACKET)\n");
						printf("\tInterface Index: %d",((struct sockaddr_ll *)temp_pcap_addr->addr)->sll_ifindex);
						printf("\tMAC Address: %s",
								packet_to_a(((struct sockaddr_ll *)temp_pcap_addr->addr)->sll_addr,
											((struct sockaddr_ll *)temp_pcap_addr->addr)->sll_halen));
					}
				}
				if(temp_pcap_addr->netmask){
					int address_family=temp_pcap_addr->netmask->sa_family;
					if(address_family==AF_INET)		//IPv4 address family
						printf("\tIPv4 Netmask: %s",inet_ntoa(((struct sockaddr_in*)temp_pcap_addr->netmask)->sin_addr));					
				}
				if(temp_pcap_addr->broadaddr){
					int address_family=temp_pcap_addr->broadaddr->sa_family;
					if(address_family==AF_INET)
						printf("\tBroadcast Address: %s",inet_ntoa(((struct sockaddr_in*)temp_pcap_addr->broadaddr)->sin_addr));
					else if(address_family==AF_PACKET)
						printf("\tBroadcast Address: %s",packet_to_a(((struct sockaddr_ll *)temp_pcap_addr->broadaddr)->sll_addr,
																	 ((struct sockaddr_ll *)temp_pcap_addr->broadaddr)->sll_halen));
				}
				if(temp_pcap_addr->dstaddr){
					int address_family=temp_pcap_addr->dstaddr->sa_family;
					if(address_family==AF_INET)
						printf("\tDestination Address: %s",inet_ntoa(((struct sockaddr_in*)temp_pcap_addr->dstaddr)->sin_addr));
					else if(address_family==AF_PACKET)
						printf("\tDestination Address: %s", packet_to_a(((struct sockaddr_ll*)temp_pcap_addr->dstaddr)->sll_addr,
																		((struct sockaddr_ll*)temp_pcap_addr->dstaddr)->sll_halen));
				}				
				temp_pcap_addr=temp_pcap_addr->next;			
			}			
		}		
		if(temp_dev->flags==PCAP_IF_LOOPBACK)
			printf("\n\tLoopback Interface");
		printf("\n");
	}	
	pcap_freealldevs(temp_dev);
	exit(1);
}
