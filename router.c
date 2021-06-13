#include <queue.h>
#include "skel.h"

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
	struct route_table_entry *left, *right;
} __attribute__((packed)); // preluata din laboratorul 4

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
}; // preluata din laboratorul 4

struct arp_entry my_arps[20]; // tabela mea de arp
int size_arps;
queue our_messages;

int add_to_arps(uint32_t ip, uint8_t mac[6]) { 
	int t = 1;
	for (int i = 0; i < size_arps; i++) {
		if (my_arps[i].ip == ip) {
			return i;
		}
	}

	if (t == 1) {
		my_arps[size_arps].ip = ip;
		memcpy(my_arps[size_arps].mac, mac, 6);
		size_arps++;
	}
	return 0;
}

int if_in_arps(uint32_t ip) {
	for (int i = 0; i < size_arps; i++) {
		if (my_arps[i].ip == ip) {
			return i;
		}
	}
	return -1;
}

void add_to_table (struct route_table_entry *node, struct route_table_entry *new_node) {
	if (node == NULL) {
		node = new_node;
	} else {
		if ((node->mask & new_node->prefix) < node->prefix) {
			if (node->left == NULL) {
				node->left = new_node;
			} else {
				add_to_table(node->left, new_node);
			}
		} else {
			if (node->right == NULL) {
				node->right = new_node;
			} else {
				add_to_table(node->right, new_node);
			}
		}
	}
}

struct route_table_entry* create_routing_table(char* file_name) {
	FILE *fp = fopen(file_name, "r");
	struct in_addr addr_cargo;
	int t = 1;
	struct route_table_entry *table = (struct route_table_entry*) calloc(1, sizeof(struct route_table_entry));
	char buffer[100];
	while (fscanf(fp, "%s", buffer) != EOF) {
		struct route_table_entry *aux = (struct route_table_entry*)calloc(1, sizeof(struct route_table_entry));
		
		aux->left = NULL;
		aux->right = NULL;
		inet_aton(buffer, &addr_cargo);
		aux->prefix = addr_cargo.s_addr;

		fscanf(fp, "%s", buffer);
		inet_aton(buffer, &addr_cargo);
		aux->next_hop = addr_cargo.s_addr;

		fscanf(fp, "%s", buffer);
		inet_aton(buffer, &addr_cargo);
		aux->mask = addr_cargo.s_addr;

		fscanf(fp, "%s", buffer);
		aux->interface = atoi(buffer);
		if (t == 1) {
			t = 0;
			table = aux;
		} else {
			add_to_table(table, aux);
		}
		
	}
	return table;
}

void free_table(struct route_table_entry *table) {
	if (table == NULL) {
		return;
	}

	free_table(table->left);
	free_table(table->right);
	free(table);
}

void deal_with_request(packet pack, struct arp_header* arphdr) {
	struct ether_header *eth_hdr = (struct ether_header *)pack.payload;

	add_to_arps(arphdr->spa, arphdr->sha);
	memcpy(eth_hdr->ether_dhost, arphdr->sha, sizeof(eth_hdr->ether_dhost));
	get_interface_mac(pack.interface, eth_hdr->ether_shost);
	send_arp(arphdr->spa, arphdr->tpa, eth_hdr, pack.interface, htons(ARPOP_REPLY));
	
}

struct route_table_entry* find_best_route(__u32 dest_ip, struct route_table_entry* node,
 int len, struct route_table_entry *current, int *safe) {
	if ((node->mask & dest_ip) == node->prefix && len < node->mask) {
		len = node->mask;
		current = node;
		*safe = 1;
	}
	
	if ((node->mask & dest_ip) >= node->prefix) {
		if (node->right != NULL) {
			return find_best_route(dest_ip, node->right, len, current, safe);
		} else {
			return current;
		}
	} else {
		if (node->left != NULL) {
			return find_best_route(dest_ip, node->left, len, current, safe);
		} else {
			return current;
		}
	}
}

void deal_with_reply(packet pack, struct arp_header* arphdr, struct route_table_entry *root) {
	add_to_arps(arphdr->spa, arphdr->sha);
	if (!queue_empty(our_messages)) {
		packet *aux_packet = (packet*)queue_deq(our_messages);
		struct ether_header *eth_aux_hdr = (struct ether_header*) aux_packet->payload;
		struct iphdr *ip_aux_hdr = (struct iphdr*) (aux_packet->payload + sizeof(struct ether_header));
		int len = 0, safe = 0;
		struct route_table_entry *route = find_best_route(ip_aux_hdr->daddr, root, len, root, &safe);
		
		int sure = if_in_arps(route->next_hop);
		if (sure >= 0) {
			memcpy(eth_aux_hdr->ether_dhost, my_arps[sure].mac, sizeof(my_arps[sure].mac));
			get_interface_mac(aux_packet->interface, eth_aux_hdr->ether_shost);
			send_packet(route->interface, aux_packet);
		}
	} else {
		return;
	}
}

int main (int argc, char *argv[]) {
	// vom crea tabela de rutare sub forma unui arbore binar de cautare
	struct route_table_entry* table = create_routing_table(argv[1]);
	
	packet m;
	
	our_messages = queue_create();
	int rc;

	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct arp_header *my_arp = parse_arp(m.payload);
		
		if (my_arp != NULL) {
			if (htons(my_arp->op) == ARPOP_REQUEST) {
				deal_with_request(m, my_arp);
				continue;
			} else {
				deal_with_reply(m, my_arp, table);
			}
		} else {
			// avem un pachet ICMP
			struct ether_header *eth = (struct ether_header*) m.payload;
			struct iphdr *ip = (struct iphdr*) (m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp = parse_icmp(m.payload);
			struct in_addr check;
			inet_aton(get_interface_ip(m.interface), &check);
			if (check.s_addr == ip->daddr) { // verificam daca este destinat routerului
				send_icmp(ip->saddr, ip->daddr, eth->ether_shost, eth->ether_dhost, ICMP_ECHOREPLY, icmp->code, m.interface, 0, 0);
			} else { // pachetul este pentru alta statie
				if (ip->ttl < 2) { // cazul in care ttl nu este valid
					send_icmp(ip->daddr, ip->saddr, eth->ether_shost, eth->ether_dhost, 11, 0, 0, 0, 0);
					continue;
				}
				if (ip_checksum(ip, sizeof(struct iphdr)) == 0) {
					int len = 0, safe = 0;
					struct route_table_entry *route = find_best_route(ip->daddr, table, len, table, &safe);
					if (safe != 0) { // a fost gasita o ruta
					
						int sure = if_in_arps(route->next_hop);
						if (sure >= 0) {
							ip->ttl--;
							memcpy(eth->ether_dhost, my_arps[sure].mac, 6);
							get_interface_mac(route->interface, eth->ether_shost);
							ip->check = 0;
							ip->check = ip_checksum(ip, sizeof(struct iphdr));
							send_packet(route->interface, &m);
						} else {
							ip->ttl--;
							struct in_addr aux_addr;
							packet queue_packet;
							memcpy(&queue_packet, &m, sizeof(packet));
							queue_enq(our_messages, &queue_packet);
					
							for (int i = 0; i < 6; i++) {
								eth->ether_dhost[i] = 0xFF;
							}
							eth->ether_type = 1544;
							get_interface_mac(route->interface, eth->ether_shost);
							
							inet_aton(get_interface_ip(route->interface), &aux_addr);
							send_arp(route->next_hop, aux_addr.s_addr, eth, route->interface, htons(ARPOP_REQUEST));
							continue;
						}
					} else {
						send_icmp_error(ip->saddr, ip->daddr, eth->ether_shost, eth->ether_dhost, 3, 0, 0);
					}
				}
			}
		}
	}

	free_table(table);
	return 0;
}