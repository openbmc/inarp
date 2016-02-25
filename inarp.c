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
#include <err.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define ETH_ARP_FRAME_LEN ( \
	sizeof(struct ethhdr) + \
	sizeof(struct arphdr) + \
	((ETH_ALEN + sizeof(struct in_addr)) * 2))

struct arp_packet {
	struct ethhdr eh;
	struct arphdr arp;
	uint8_t		src_mac[ETH_ALEN];
	struct in_addr	src_ip;
	uint8_t		dest_mac[ETH_ALEN];
	struct in_addr	dest_ip;
} __attribute__((packed));

static int send_arp_packet(int fd,
		    int ifindex,
		    unsigned char *src_mac,
		    struct in_addr *src_ip,
		    unsigned char *dest_mac,
		    struct in_addr *dest_ip)
{
	struct sockaddr_ll socket_address;
	struct arp_packet arp;
	int rc;

	memset(&arp, 0, sizeof(arp));

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
	memcpy(arp.eh.h_dest, (void *)dest_mac, ETH_ALEN);
	memcpy(arp.eh.h_source, (void *)src_mac, ETH_ALEN);
	arp.eh.h_proto = htons(ETH_P_ARP);

	/* Fill InARP request data for ethernet + ipv4 */
	arp.arp.ar_hrd = htons(ARPHRD_ETHER);
	arp.arp.ar_pro = htons(ETH_P_ARP);
	arp.arp.ar_hln = ETH_ALEN;
	arp.arp.ar_pln = 4;
	arp.arp.ar_op = htons(ARPOP_InREPLY);

	/* fill arp ethernet mac & ipv4 info */
	memcpy(&arp.src_mac, src_mac, sizeof(arp.src_mac));
	memcpy(&arp.src_ip, src_ip, sizeof(arp.src_ip));
	memcpy(&arp.dest_mac, dest_mac, sizeof(arp.dest_mac));
	memcpy(&arp.dest_ip, dest_ip, sizeof(arp.dest_ip));

	/* send the packet */
	rc = sendto(fd, &arp, sizeof(arp), 0,
			     (struct sockaddr *)&socket_address,
			     sizeof(socket_address));
	if (rc < 0)
		warn("failure sending ARP response");

	return rc;
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

static int get_local_ipaddr(int fd, const char *ifname, struct in_addr *addr)
{
	struct sockaddr_in *sa;
	struct ifreq ifreq;
	int rc;

	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);

	rc = ioctl(fd, SIOCGIFADDR, &ifreq);
	if (rc) {
		warn("Error querying local address for %s", ifname);
		return -1;
	}

	if (ifreq.ifr_addr.sa_family != AF_INET) {
		warnx("Unknown address family %d in address response",
		       ifreq.ifr_addr.sa_family);
		return -1;
	}

	sa = (struct sockaddr_in *)&ifreq.ifr_addr;
	memcpy(addr, &sa->sin_addr, sizeof(*addr));
	return 0;
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s <interface>\n", progname);
}

int main(int argc, char **argv)
{
	/*buffer for ethernet frame */
	static unsigned char buffer[ETH_FRAME_LEN];
	static struct ifreq ifreq_buffer;
	const char *ifname;
	int fd, ret;

	if (argc < 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	ifname = argv[1];

	if (strlen(ifname) > IFNAMSIZ)
		errx(EXIT_FAILURE, "Interface name '%s' is invalid", ifname);

	static unsigned char src_mac[6];
	static struct in_addr local_ip;
	int ifindex;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (fd < 0)
		err(EXIT_FAILURE, "Error opening ARP socket");

	/* Query local mac address */
	memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
	strcpy(ifreq_buffer.ifr_name, ifname);
	ret = ioctl(fd, SIOCGIFHWADDR, &ifreq_buffer);
	if (ret < 0)
		err(EXIT_FAILURE, "Error querying local MAC address");

	memcpy(src_mac, ifreq_buffer.ifr_hwaddr.sa_data, ETH_ALEN);
	show_mac_addr(ifname, src_mac);

	/* find the ifindex of the interface we're using */
	memset(&ifreq_buffer, 0x00, sizeof(ifreq_buffer));
	strcpy(ifreq_buffer.ifr_name, ifname);
	ret = ioctl(fd, SIOCGIFINDEX, &ifreq_buffer);
	if (ret < 0)
		err(EXIT_FAILURE, "Error querying interface %s", ifname);

	ifindex = ifreq_buffer.ifr_ifindex;

	/* length of the received frame */
	int length = 0;
	static struct arp_packet *inarp_req = (void *)buffer;

	while (1) {
		length = recvfrom(fd, buffer, ETH_ARP_FRAME_LEN, 0, NULL, NULL);
		if (length <= 0) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "Error recieving ARP packet");
		}

		/* is this an inarp request? */
		if (ntohs(inarp_req->arp.ar_op) != ARPOP_InREQUEST)
			continue;

		/* ... for us? */
		if (memcmp(src_mac, inarp_req->eh.h_dest, ETH_ALEN))
			continue;

		printf("src mac =%02x:%02x:%02x:%02x:%02x:%02x\n",
				inarp_req->src_mac[0],
				inarp_req->src_mac[1],
				inarp_req->src_mac[2],
				inarp_req->src_mac[3],
				inarp_req->src_mac[4],
				inarp_req->src_mac[5]);

		printf("src ip = %s\n", inet_ntoa(inarp_req->src_ip));

		ret = get_local_ipaddr(fd, ifname, &local_ip);
		/* if we don't have a local IP address to send, just drop the
		 * request */
		if (ret)
			continue;

		send_arp_packet(fd, ifindex,
				    inarp_req->dest_mac,
				    &local_ip,
				    inarp_req->src_mac,
				    &inarp_req->src_ip);

		memset(buffer, 0, sizeof(buffer));
	}
	close(fd);
	return 0;
}
