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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define ETH_ARP_FRAME_LEN ( \
	sizeof(struct ethhdr) + \
	sizeof(struct arphdr) + \
	((ETH_ALEN + 4) * 2))

struct ARP_DATA {
	unsigned char src_mac[ETH_ALEN];
	unsigned char src_ip[4];
	unsigned char dest_mac[ETH_ALEN];
	unsigned char dest_ip[4];
};
struct ETH_ARP_PACKET {
	struct ethhdr eh;
	struct arphdr arp;
	struct ARP_DATA arp_data;
};

struct ETH_ARP_PACKET *inarp_req;

static int send_arp_packet(int fd,
		    int ifindex,
		    struct ETH_ARP_PACKET *eth_arp,
		    __be16 ar_op,
		    unsigned char *src_mac,
		    unsigned char *src_ip,
		    unsigned char *dest_mac, unsigned char *dest_ip)
{
	int send_result = 0;
	struct ethhdr *eh = &eth_arp->eh;
	struct arphdr *arp = &eth_arp->arp;
	struct ARP_DATA *arp_data = &eth_arp->arp_data;
	struct sockaddr_ll socket_address;

	/* Prepare our link-layer address: raw packet interface,
	 * using the ifindex interface, receiving ARP packets
	 */
	socket_address.sll_family = PF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_ARP);
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_hatype = ARPHRD_ETHER;
	socket_address.sll_pkttype = PACKET_OTHERHOST;
	socket_address.sll_halen = ETH_ALEN;
	memcpy(socket_address.sll_addr, dest_mac, ETH_ALEN);

	/* set the frame header */
	memcpy((void *)eh->h_dest, (void *)dest_mac, ETH_ALEN);
	memcpy((void *)eh->h_source, (void *)src_mac, ETH_ALEN);
	eh->h_proto = htons(ETH_P_ARP);

	/* Fill InARP request data for ethernet + ipv4 */
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_ARP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op = htons(ar_op);

	/* fill arp ethernet mac & ipv4 info */
	arp_data = (void *)(arp + 1);
	memcpy(arp_data->src_mac, (void *)src_mac, ETH_ALEN);
	memcpy(arp_data->src_ip, src_ip, 4);
	memcpy(arp_data->dest_mac, (void *)dest_mac, ETH_ALEN);
	memcpy(arp_data->dest_ip, dest_ip, 4);

	/* send the packet */
	send_result = sendto(fd, eth_arp, ETH_ARP_FRAME_LEN, 0,
			     (struct sockaddr *)&socket_address,
			     sizeof(socket_address));
	if (send_result == -1) {
		printf("sendto: [%s]\n", strerror(errno));
	}
	return send_result;
}

static void show_mac_addr(const char *name, unsigned char *mac_addr)
{
	int i;
	printf("%s MAC address: ", name);
	for (i = 0; i < 6; i++) {
		printf("%.2X%c", (unsigned char)mac_addr[i],
		       (i == 5) ? '\n' : ':');
	}
	return;
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s <interface>\n", progname);
}

int main(int argc, char **argv)
{
	int fd, ret;
	/*buffer for ethernet frame */
	static unsigned char buffer[ETH_FRAME_LEN];
	int send_result = 0;
	static struct ifreq ifreq_buffer;
	const char *ifname;

	if (argc < 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	ifname = argv[1];

	if (strlen(ifname) > IFNAMSIZ) {
		fprintf(stderr, "Interface name '%s' is invalid\n", ifname);
		return EXIT_FAILURE;
	}

	static unsigned char src_mac[6];
	static unsigned char src_ip[4];
	int ifindex;

	if (((fd = socket(AF_PACKET, SOCK_PACKET, htons(ETH_P_ARP)))) == -1) {
		printf("socket: [%s]\n", strerror(errno));
		exit(-1);
	}

	/* Query local mac address */
	memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
	strcpy(ifreq_buffer.ifr_name, ifname);
	ret = ioctl(fd, SIOCGIFHWADDR, &ifreq_buffer);
	if (ret == -1) {
		printf("ioctl2: [%s]\n", strerror(errno));
		close(fd);
		exit(-1);
	}
	memcpy(src_mac, ifreq_buffer.ifr_hwaddr.sa_data, ETH_ALEN);
	show_mac_addr(ifname, src_mac);

	/* find the ifindex of the interface we're using */
	memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
	strcpy(ifreq_buffer.ifr_name, ifname);
	ret = ioctl(fd, SIOCGIFINDEX, &ifreq_buffer);
	if (ret == -1) {
		printf("ioctl4: [%s]\n", strerror(errno));
		close(fd);
		exit(-1);
	}
	ifindex = ifreq_buffer.ifr_ifindex;

	/* length of the received frame */
	int length = 0;
	static struct ETH_ARP_PACKET *inarp_req =
		(struct ETH_ARP_PACKET *)buffer;
	static struct ETH_ARP_PACKET inarp_resp;

	while (1) {
		/* get local ip address */
		memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
		strcpy(ifreq_buffer.ifr_name, ifname);
		ret = ioctl(fd, SIOCGIFADDR, &ifreq_buffer);
		if (ret == -1) {
			sleep(1);
			continue;
		}

		if (AF_INET == ifreq_buffer.ifr_addr.sa_family) {
			memcpy(src_ip, &ifreq_buffer.ifr_addr.sa_data[2], 4);
		} else {
			printf("unknown address family [%d]!\n",
			       ifreq_buffer.ifr_addr.sa_family);
			sleep(1);
			continue;
		}

		memset((void *)&inarp_resp, 0, sizeof inarp_resp);
		length = recvfrom(fd, buffer, ETH_ARP_FRAME_LEN, 0, NULL, NULL);
		if (length == -1) {
			sleep(1);
		}
		if (0 == memcmp(src_mac, inarp_req->eh.h_dest, ETH_ALEN)) {
			if (ntohs(inarp_req->arp.ar_op) == ARPOP_InREQUEST) {

				printf
				    ("src mac =%02x:%02x:%02x:%02x:%02x:%02x\r\n",
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
				if (((fd_1 =
				      socket(AF_PACKET, SOCK_RAW, 0))) == -1) {
					printf("socket: [%s]\n",
					       strerror(errno));
					exit(-1);
				}
				send_result =
				    send_arp_packet(fd_1, ifindex, &inarp_resp,
						    ARPOP_InREPLY,
						    inarp_req->arp_data.
						    dest_mac, src_ip,
						    inarp_req->arp_data.src_mac,
						    inarp_req->arp_data.src_ip);
				close(fd_1);
				if (send_result == -1) {
					printf("[Rsp] sendto: [%s]\n",
					       strerror(errno));
					sleep(1);
					continue;
				}
			}
			memset(buffer, 0, sizeof(buffer));
		}
	}
	close(fd);
	return 0;
}
