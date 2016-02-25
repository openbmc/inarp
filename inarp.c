/******************************************************************************
*	Copyright 2016 Foxconn
*
*	Licensed under the Apache License, Version 2.0 (the "License");
*	you may not use this file except in compliance with the License.
*	You may obtain a copy of the License at
*
*		http://www.apache.org/licenses/LICENSE-2.0
*
*	Unless required by applicable law or agreed to in writing, software
*	distributed under the License is distributed on an "AS IS" BASIS,
*	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*	See the License for the specific language governing permissions and
*	limitations under the License.
******************************************************************************/
#define MAX_SERVER_NODE 24
#define SKU1_MAX_SERVER_NODES 24

#define ETH_ARP_FRAME_LEN (	sizeof(struct ethhdr)+\
							sizeof(struct arphdr)+\
							((ETH_ALEN+4)*2)\
							)

struct ARP_DATA {
	unsigned char src_mac [ETH_ALEN];//source mac addr
	unsigned char src_ip  [4];		//source ip addr
	unsigned char dest_mac[ETH_ALEN];//dest mac addr
	unsigned char dest_ip [4];		//dest ip 
};
struct ETH_ARP_PACKET {
	struct ethhdr eh;
	struct arphdr arp;
	struct ARP_DATA arp_data;
};

struct ETH_ARP_PACKET *inarp_req;

static          char based_mac[6] = {0,0,0,0,0,0};
int send_arp_packet(int fd,
					int ifindex,
					struct ETH_ARP_PACKET *eth_arp,
					__be16 ar_op,
					unsigned char *src_mac,
					unsigned char *src_ip,
					unsigned char *dest_mac,
					unsigned char *dest_ip
					)
{
	int send_result = 0;
	struct ethhdr *eh = &eth_arp->eh;
	struct arphdr *arp = &eth_arp->arp;
	struct ARP_DATA *arp_data = &eth_arp->arp_data;
	/*target address*/
	struct sockaddr_ll socket_address;
	/*prepare sockaddr_ll*/
	/*RAW communication*/
	socket_address.sll_family   = PF_PACKET;	
	/*we don't use a protocoll above ethernet layer
	  ->just use anything here*/
	socket_address.sll_protocol = htons(ETH_P_ARP);
	/*index of the network device
	see full code later how to retrieve it*/
	socket_address.sll_ifindex  = ifindex;
	/*ARP hardware identifier is ethernet*/
	socket_address.sll_hatype   = ARPHRD_ETHER;
	/*target is another host*/
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	/*address length*/
	socket_address.sll_halen    = ETH_ALEN;		
	memcpy(socket_address.sll_addr, dest_mac, ETH_ALEN);
	/*set the frame header*/
	memcpy((void*)eh->h_dest, (void*)dest_mac, ETH_ALEN);
	memcpy((void*)eh->h_source, (void*)src_mac, ETH_ALEN);
	eh->h_proto = htons(ETH_P_ARP);
	/*fill InARP request data for ethernet + ipv4*/
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_ARP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op  = htons(ar_op);
	//fill arp ethernet mac & ipv4 info
	arp_data = (void*)(arp + 1);
	memcpy(arp_data->src_mac , (void*)src_mac, ETH_ALEN);	//source mac addr
	memcpy(arp_data->src_ip  , src_ip, 4);					//source ip addr
	memcpy(arp_data->dest_mac, (void*)dest_mac, ETH_ALEN);	//dest mac addr
	memcpy(arp_data->dest_ip , dest_ip, 4);					//dest ip 
	/*send the packet*/
	send_result = sendto(fd, eth_arp, ETH_ARP_FRAME_LEN, 0, 
	      (struct sockaddr*)&socket_address, sizeof(socket_address));
	if (send_result == -1) {
   		printf("sendto: [%s]\n", strerror(errno));
	}
	return send_result;
}
void show_mac_addr(char *name, unsigned char *mac_addr)
{
	int i;
	printf("%s MAC address: ", name);
	for( i = 0; i < 6; i++ )
    {
        printf("%.2X%c", (unsigned char)mac_addr[i], (i == 5) ? '\n': ':');
    }
	return;
}
void show_ip_addr(char *desc, unsigned char *ip_addr)
{
	int i;
    printf("%s IPv4 address: ", desc);
	for(i = 0; i < 4; i++ )
    {
	    printf("%d%c", (unsigned char)ip_addr[i], (i == 3) ? '\n': '.');
    }
}
void dump_data(char *desc, unsigned char *buffer, int length)
{
	int i;
	printf("%s & length is [%d]:\n", desc, length); 
	for (i=0; i<length; i++) {
		printf ("[%02X]", 0xff & buffer[i]);
		if ((i&0xf)==0x7) printf(" - ");
		if ((i&0xf)==0xf) printf("\n");
	}
	printf("\n");
}
void get_mac_address_for_node_id(int node_id, char *mac_addr) {
	int i;
	int add = node_id;
	int carry = 0;
	int mac;
	for (i=5; i>=0;i--) {
		mac = (int)based_mac[i];
		mac += (add + carry);
		add = 0;
		if (mac > 255) {
			carry = 1;
			mac -= 256;
		} else {
			carry = 0;
		}
		mac_addr[i] = (char)mac;
	}
}
//return node_id or -1 for error
int get_node_id_by_mac_address(unsigned char *target_mac_addr) {
	char mac_addr[ETH_ALEN];
	int i;
	for (i=0; i<MAX_SERVER_NODE; i++) {
		get_mac_address_for_node_id(i, mac_addr);
		if (0 == memcmp(target_mac_addr, mac_addr, ETH_ALEN))
			break;
	}
	if (i != MAX_SERVER_NODE) {
//		int j;
//		printf("mac_address for node[%d]:", i+1);
//		for (j=0; j<6; j++)
//			printf("%02x:", 0xff & mac_addr[j]);
//		printf("\n");
		return i;
	} else
		return -1;
}
#if ENABLE_MONOTONIC_SYSCALL
#include <sys/syscall.h>
/* Old glibc (< 2.3.4) does not provide this constant. We use syscall
 * directly so this definition is safe. */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

unsigned FAST_FUNC monotonic_sec(void)
{
	struct timespec ts;
	get_mono(&ts);
	return ts.tv_sec;
}

#else

unsigned monotonic_sec(void)
{
	return time(NULL);
}
#endif
//query ip addr for server node w/ mac addr
//inarp "ethX" "peer mac addr(xx:xx:xx:xx:xx:xx)"
//inarp daemon to handle inarp packets
//inarp "ethX" "file for storing node list"
void InvARPServerTask(
                                  /** the internal task ID of this task (in) */
                                  ULONG thread_input
                                )
{
	int fd, ret;
	/*buffer for ethernet frame*/
	static unsigned char buffer[ETH_FRAME_LEN]; /* single packets are usually not bigger than 8192 bytes */
	int send_result = 0;
    static struct ifreq ifreq_buffer;
 
	/*our MAC address*/
	static unsigned char src_mac[6];
	static unsigned char src_ip[4];
	int ifindex;
//	int InARP_SERVER;

	if (((fd = socket (AF_PACKET, SOCK_PACKET, htons(ETH_P_ARP)))) == -1) {
//	if (((fd = socket (AF_PACKET, SOCK_RAW, 0))) == -1) {
    	printf("socket: [%s]\n", strerror(errno));
		exit(-1);
	}
	//local mac address
	memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
	strcpy(ifreq_buffer.ifr_name, "ncsi0");
	ret = ioctl(fd, SIOCGIFHWADDR, &ifreq_buffer);
	if (ret == -1) {
   		printf("ioctl2: [%s]\n", strerror(errno));
		close(fd);
		exit(-1);
	}
	memcpy(src_mac, ifreq_buffer.ifr_hwaddr.sa_data, ETH_ALEN);
	show_mac_addr("ncsi0", src_mac);
    //interface index
	memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
	strcpy(ifreq_buffer.ifr_name, "ncsi0");
	ret = ioctl(fd, SIOCGIFINDEX, &ifreq_buffer);
	if (ret == -1) {
   		printf("ioctl4: [%s]\n", strerror(errno));
		close(fd);
		exit(-1);
	}
	ifindex = ifreq_buffer.ifr_ifindex;

	int length = 0; /*length of the received frame*/
	static struct ETH_ARP_PACKET *inarp_req = (struct ETH_ARP_PACKET *)buffer; /* single packets are usually not bigger than 8192 bytes */
	static struct ETH_ARP_PACKET inarp_resp; /* single packets are usually not bigger than 8192 bytes */
	static struct {
		unsigned char dest_ip[4];
		struct timespec update_time;
	} node[SKU1_MAX_SERVER_NODES];
	struct timespec current_time;
	//argv[2]: file name used for storing node ip list
	//			line format in file: <node_id> <mac_addr> <ip_addr>
	//get based address via EMS
	//set socket as async
//	fcntl(fd, F_SETFL,O_NONBLOCK|FASYNC);
	//got based address
	while (1) {
		//get local ip address
		memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
		strcpy(ifreq_buffer.ifr_name, "ncsi0");
		ret = ioctl(fd, SIOCGIFADDR, &ifreq_buffer);
		if (ret == -1) {
//	   		printf("ioctl3: [%s]\n", strerror(errno));
	   		sleep(1);
	   		continue;
		}

	    if (AF_INET == ifreq_buffer.ifr_addr.sa_family) {
			memcpy(src_ip, &ifreq_buffer.ifr_addr.sa_data[2], 4);
//			show_ip_addr("local", (unsigned char *)&ifreq_buffer.ifr_addr.sa_data[2]);
			//show_ip_addr("local", src_ip);
		} else {
		    printf("unknown address family [%d]!\n", ifreq_buffer.ifr_addr.sa_family);
	   		sleep(1);
	   		continue;
		}

	    memset((void*)&inarp_resp, 0, sizeof inarp_resp);
		length = recvfrom(fd, buffer, ETH_ARP_FRAME_LEN, 0, NULL, NULL);
		if (length == -1) {
			sleep(1);
		}
//		printf("length = %d\r\nfd = %d\r\n", length, fd);
		current_time.tv_sec = (unsigned)monotonic_sec();
		if (0 == memcmp(src_mac, inarp_req->eh.h_dest, ETH_ALEN)) {
			if (ntohs(inarp_req->arp.ar_op) == ARPOP_InREQUEST) {	//get a inverse arp request
//				printf("[Rsp] InRequest\n");
				//dump_data("got InARP request packet", buffer, length); 
				//send inarp response
				
				printf("src mac =%02x:%02x:%02x:%02x:%02x:%02x\r\n",
							inarp_req->arp_data.src_mac[0],
							inarp_req->arp_data.src_mac[1],
							inarp_req->arp_data.src_mac[2],
							inarp_req->arp_data.src_mac[3],
							inarp_req->arp_data.src_mac[4],
							inarp_req->arp_data.src_mac[5]
				);
				printf("src ip =%d:%d:%d:%d\r\n",
							inarp_req->arp_data.src_ip[0],
							inarp_req->arp_data.src_ip[1],
							inarp_req->arp_data.src_ip[2],
							inarp_req->arp_data.src_ip[3]
					);
				int fd_1;
				if (((fd_1 = socket (AF_PACKET, SOCK_RAW, 0))) == -1) {
 				   	printf("socket: [%s]\n", strerror(errno));
					exit(-1);
				}
				send_result = send_arp_packet(fd_1, ifindex, &inarp_resp, ARPOP_InREPLY,
									inarp_req->arp_data.dest_mac, src_ip,
									inarp_req->arp_data.src_mac, inarp_req->arp_data.src_ip);
				close(fd_1);
				if (send_result == -1) {
					printf("[Rsp] sendto: [%s]\n", strerror(errno));
			   		sleep(1);
			   		continue;
				}
			}
//			} else if (ntohs(inarp_req->arp.ar_op) == ARPOP_InREPLY) {	//get a InARP Response
//				int node_id;
//				printf("[Rsp] InReply\n");
//				node_id = get_node_id_by_mac_address(inarp_req->arp_data.src_mac);
//				if (node_id == -1) {
//					//invalid node
//					printf("%02x:%02x:%02x:%02x:%02x:%02x does not belong to this rack.",
//							inarp_req->arp_data.src_mac[0],
//							inarp_req->arp_data.src_mac[1],
//							inarp_req->arp_data.src_mac[2],
//							inarp_req->arp_data.src_mac[3],
//							inarp_req->arp_data.src_mac[4],
//							inarp_req->arp_data.src_mac[5]
//					);
//				} else {
					//valid node id
//					node[node_id].update_time.tv_sec = current_time.tv_sec;
					//update or remain node's ip
//					if ((0 != memcmp(node[node_id].dest_ip, inarp_req->arp_data.src_ip, 4))) {
						//ip address is changed.
//						static char ipv4_addr[16];
//						printf("[Rsp] update node[%d] ip @ %u\n", node_id+1, (unsigned)current_time.tv_sec);
//							show_mac_addr("[Rsp] ", inarp_req->arp_data.src_mac);
//							show_ip_addr("[Rsp] ", inarp_req->arp_data.src_ip);
//							memcpy(node[node_id].dest_ip, inarp_req->arp_data.src_ip, 4);
//						sprintf(ipv4_addr, "%d.%d.%d.%d", 
//									inarp_req->arp_data.src_ip[0],
//									inarp_req->arp_data.src_ip[1],
//									inarp_req->arp_data.src_ip[2],
//									inarp_req->arp_data.src_ip[3]);
//						printf("[Rsp] update node[%d] ip @ %u\n", node_id+1, (unsigned)current_time.tv_sec);
//			}
		memset(buffer, 0, sizeof(buffer));
		}
	}
	close(fd);
	return 0;
}
