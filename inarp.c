/******************************************************************************
 * Copyright 2016 Foxconn
 * Copyright 2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

struct eth_addr {
	uint8_t		eth_addr[ETH_ALEN];
} __attribute__((packed));

struct arp_packet {
	struct ethhdr	eh;
	struct arphdr	arp;
	struct eth_addr	src_mac;
	struct in_addr	src_ip;
	struct eth_addr	dest_mac;
	struct in_addr	dest_ip;
} __attribute__((packed));

struct interface {
	int		ifindex;
	char		ifname[IFNAMSIZ+1];
	struct eth_addr	eth_addr;
};

struct inarp_ctx {
	int			socket;
	struct interface	*interfaces;
	unsigned int		n_interfaces;
};

static int send_arp_packet(int fd,
		int ifindex,
		const struct eth_addr *src_mac,
		const struct in_addr *src_ip,
		const struct eth_addr *dest_mac,
		const struct in_addr *dest_ip)
{
	struct sockaddr_ll addr;
	struct arp_packet arp;
	int rc;

	memset(&arp, 0, sizeof(arp));

	/* Prepare our link-layer address: raw packet interface,
	 * using the ifindex interface, receiving ARP packets
	 */
	addr.sll_family = PF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	addr.sll_ifindex = ifindex;
	addr.sll_hatype = ARPHRD_ETHER;
	addr.sll_pkttype = PACKET_OTHERHOST;
	addr.sll_halen = ETH_ALEN;
	memcpy(addr.sll_addr, dest_mac, ETH_ALEN);

	/* set the frame header */
	memcpy(arp.eh.h_dest, dest_mac, ETH_ALEN);
	memcpy(arp.eh.h_source, src_mac, ETH_ALEN);
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
			(struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0)
		warn("failure sending ARP response");

	return rc;
}

static const char *eth_mac_to_str(const struct eth_addr *mac_addr)
{
	static char mac_str[ETH_ALEN * (sizeof("00:") - 1)];
	const uint8_t *addr = mac_addr->eth_addr;

	snprintf(mac_str, sizeof(mac_str),
			"%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5]);

	return mac_str;
}

static int do_ifreq(int fd, unsigned long type,
		const char *ifname, struct ifreq *ifreq)
{
	memset(ifreq, 0, sizeof(*ifreq));
	strncpy(ifreq->ifr_name, ifname, sizeof(ifreq->ifr_name));

	return ioctl(fd, type, ifreq);
}

static int get_local_ipaddr(int fd, const char *ifname, struct in_addr *addr)
{
	struct sockaddr_in *sa;
	struct ifreq ifreq;
	int rc;

	rc = do_ifreq(fd, SIOCGIFADDR, ifname, &ifreq);
	if (rc) {
		warn("Error querying local IP address for %s", ifname);
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

static int get_local_hwaddr(int fd, const char *ifname, struct eth_addr *addr)
{
	struct ifreq ifreq;
	int rc;

	rc = do_ifreq(fd, SIOCGIFHWADDR, ifname, &ifreq);
	if (rc) {
		warn("Error querying local MAC address for %s", ifname);
		return -1;
	}

	memcpy(addr, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

static int get_ifindex(int fd, const char *ifname, int *ifindex)
{
	struct ifreq ifreq;
	int rc;

	rc = do_ifreq(fd, SIOCGIFINDEX, ifname, &ifreq);
	if (rc < 0) {
		warn("Error querying interface %s", ifname);
		return -1;
	}

	*ifindex = ifreq.ifr_ifindex;
	return 0;
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s <interface>\n", progname);
}

int main(int argc, char **argv)
{
	struct arp_packet inarp_req;
	struct in_addr local_ip;
	struct inarp_ctx inarp;
	struct interface *iface;
	ssize_t len;
	int ret;

	if (argc < 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (strlen(argv[1]) > IFNAMSIZ)
		errx(EXIT_FAILURE, "Interface name '%s' is invalid",
				argv[1]);

	memset(&inarp, 0, sizeof(inarp));

	/* prepare for a single interface */
	inarp.interfaces = calloc(1, sizeof(inarp.interfaces[0]));
	inarp.n_interfaces = 1;
	iface = &inarp.interfaces[0];

	strncpy(iface->ifname, argv[1], sizeof(iface->ifname));

	inarp.socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (inarp.socket < 0)
		err(EXIT_FAILURE, "Error opening ARP socket");

	ret = get_ifindex(inarp.socket, iface->ifname, &iface->ifindex);
	if (ret)
		exit(EXIT_FAILURE);

	ret = get_local_hwaddr(inarp.socket, iface->ifname, &iface->eth_addr);
	if (ret)
		exit(EXIT_FAILURE);

	printf("%s MAC address: %s\n", iface->ifname,
			eth_mac_to_str(&iface->eth_addr));

	while (1) {
		len = recvfrom(inarp.socket, &inarp_req, sizeof(inarp_req), 0,
				NULL, NULL);
		if (len <= 0) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "Error recieving ARP packet");
		}

		/* Is this packet large enough for an inarp? */
		if ((size_t)len < sizeof(inarp_req))
			continue;

		/* ... is it an inarp request? */
		if (ntohs(inarp_req.arp.ar_op) != ARPOP_InREQUEST)
			continue;

		/* ... for us? */
		if (memcmp(&iface->eth_addr, inarp_req.eh.h_dest, ETH_ALEN))
			continue;

		printf("src mac:  %s\n", eth_mac_to_str(&inarp_req.src_mac));
		printf("src ip:   %s\n", inet_ntoa(inarp_req.src_ip));

		ret = get_local_ipaddr(inarp.socket, iface->ifname, &local_ip);
		/* if we don't have a local IP address to send, just drop the
		 * request */
		if (ret)
			continue;

		printf("local ip: %s\n", inet_ntoa(local_ip));

		send_arp_packet(inarp.socket, iface->ifindex,
				&inarp_req.dest_mac,
				&local_ip,
				&inarp_req.src_mac,
				&inarp_req.src_ip);
	}
	close(inarp.socket);
	return 0;
}
