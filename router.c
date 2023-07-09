/*
The router should only work by forwarding packets. The router will first check on all of its interfaces
for a network packet, then it will proceed to enqueue the packets and start processing them.

*/


#include "include/skel.h"
#include <pthread.h>
#include <signal.h>

// Create our queue where packets will reside
queue q_store_packets;

// Create the hashtable that stores IP packets as value and IP addresses as keys
struct hashtable_entry *hashtable = NULL;

pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize router interfaces
const char p_ip_interface_r0[12] = "192.168.0.1";
const char p_ip_interface_r1[12] = "192.168.1.1";
const char p_ip_interface_r2[12] = "192.168.2.1";
const char p_ip_interface_r3[12] = "192.168.3.1";
uint32_t ip_interface_r0;
uint32_t ip_interface_r1;
uint32_t ip_interface_r2;
uint32_t ip_interface_r3;
uint32_t router_interfaces[ROUTER_NUM_INTERFACES];
int interfaces[ROUTER_NUM_INTERFACES];

struct arp_entry *arp_table;
struct route_table_entry *rtable;

int rtable_size=0, arp_table_len=0;

void textToHex(const char* text) {
    int length = strlen(text);
    for (int i = 0; i < length; i++) {
        printf("%02X", text[i]);
    }
    printf("\n");
}

uint16_t ip_checksum2(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

void initializeInterfaces () {
	ip_interface_r0 = inet_addr(p_ip_interface_r0);
	ip_interface_r1 = inet_addr(p_ip_interface_r1);
	ip_interface_r2 = inet_addr(p_ip_interface_r2);
	ip_interface_r3 = inet_addr(p_ip_interface_r3);
	router_interfaces[0] = ip_interface_r0;
	router_interfaces[1] = ip_interface_r1;
	router_interfaces[2] = ip_interface_r2;
	router_interfaces[3] = ip_interface_r3;
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
    	router_interfaces[i] = ntohl(router_interfaces[i]);
	}
	printf("Successfully initialized router interfaces\n");
}

// Signal handler function
// Signum is automatically written by the OS in the case of a signal received
void handle_termination(int signum) {
    // Cleanup operations
    free(arp_table);
    free(rtable);

    printf("Successfully cleaned up\n");
	// Terminate the program
    exit(signum);
}

// Listener thread
void *listenForPackets(void *arg){
	// printf("Listener thread - started!\n");
	int rc;
	// packet m;
	packet m;
	// printf("Listener thread - before creating the queue\n");
	
	// printf("Listener thread - created the queue\n");
	
	while (1) {
		// printf("Listener thread - listening\n");
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		
		// This means we've got an incoming packet
		// Enqueue the message
		if (rc >= 0) {
			// printf("Listener thread - Received new packet\n");
			// printf("Now printing m received\n");
			// struct ether_header *eth_hdr = (struct ether_header *)m.payload;
			// struct arphdr *arp_hdr = (struct arphdr *)(m.payload + sizeof(struct ether_header));
			// struct arp_request *arp_req = (struct arp_request *)(m.payload + sizeof(struct ether_header) + sizeof(struct arphdr));
			// printf("Listener thread - arp_req->ar_tip: %u\n", ntohl(arp_req->ar_tip));

			
			// rc = 0;
			// Print received packet details
			// printf("Payload: \n");
			// textToHex(m.payload);
			// printf("Size of the received packet: %d\n", m.len);
			packet *aux = malloc(sizeof(packet));
			memcpy(aux->payload, m.payload, m.len);
			aux->len = m.len;
			aux->interface=m.interface;

			// printf("Now printing m_aux constructed\n");
			//  eth_hdr = (struct ether_header *)m.payload;
			//  arp_hdr = (struct arphdr *)(m.payload + sizeof(struct ether_header));
			//  arp_req = (struct arp_request *)(m.payload + sizeof(struct ether_header) + sizeof(struct arphdr));


			//Print constructed packet details
			// printf("Constructed new packet with the form:\n");
			// printf("Payload: \n");
			// textToHex(aux->payload);
			// printf("Size of the received packet: %d\n", aux->len);

			pthread_mutex_lock(&queue_mutex);
			// size of the payload
			queue_enq(q_store_packets, aux);
			pthread_mutex_unlock(&queue_mutex);
			pthread_cond_signal(&queue_cond);
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t tid;

	initializeInterfaces();
	
	// Allocate memory for routing table and arp table
	rtable = malloc(sizeof(struct route_table_entry) * 64285);
	arp_table = malloc(sizeof(struct  arp_entry) * 100);
	q_store_packets = queue_create();

	DIE(rtable == NULL, "Could not allocate memory for routing table!\n");
	DIE(arp_table == NULL, "Could not allocate memory for ARP table!\n");

	// Set up signal handler for SIGINT
    signal(SIGINT, handle_termination);

	// Initialize interfaces
	init();
	
	rtable_size = read_rtable(rtable);
    fprintf(stderr, "Done parsing ROUTING table.\n");

    printf("rtable_size is: %d\n", rtable_size);
	parse_arp_table();
	fprintf(stderr, "Done parsing ARP table.\n");


	// Run the listener thread
    int td = pthread_create(&tid, NULL, listenForPackets, NULL);
	DIE(td != 0, "Could not create listener thread!\n");
	fprintf(stderr, "Sucessfully started a new thread.\n");
	
	// Main thread
	// We'll use a condition variable coupled with a mutex to protect access to the queue of packets
	// The main threads acquires the lock, and while the queue is empty, it will wait until signaled by the listener thread
	// Note that while waiting for the cond. var, the lock is released such that the listener can acquire the lock
	// such that after it has finished processing, the listener signals the main thread to continue processing
	while (1) {
		pthread_mutex_lock(&queue_mutex);
		
		while (queue_empty(q_store_packets)) {
			// printf("Main thread - waiting\n");
			pthread_cond_wait(&queue_cond, &queue_mutex);
		}
		// printf("Main thread - Found packets inside the queue\n");
		// packet m_aux;
		// memcpy(&m_aux, queue_deq(q_store_packets), icmp_packet_len);
		packet *m_aux = (packet *)queue_deq(q_store_packets);
		pthread_mutex_unlock(&queue_mutex);

		// printf("Processing packet: %s\n", m_aux->payload);

		// Process the packet
		// Cast an ethernet frame
		// We expect every packet to be an ethernet frame
		DIE(m_aux == NULL, "m_aux null\n");
		// printf("m_aux->len is: %d", m_aux->len);
		struct ether_header *eth_hdr = (struct ether_header *)m_aux->payload;
		// printf("eth_hdr received is: %d\n", eth_hdr->ether_type);
		switch (ntohs(eth_hdr->ether_type)) {
			case ETHERTYPE_IP: {
				// Handle IP packet
				int var = 0;
				printf("Found IP packet\n");
				struct iphdr *ip_hdr = (struct iphdr *)(m_aux->payload + sizeof(struct ether_header));
				// Calculate the checksum for the IP header
				// printf("Checksum received is: %d\n", ip_hdr->check);
				uint16_t checksum_packet = ip_hdr->check;
				ip_hdr->check = 0;
				uint16_t computed_checksum = ip_checksum2(ip_hdr, ip_hdr->ihl<<2);
				// printf("Checksum computed is: %d\n", computed_checksum);
				if (checksum_packet != computed_checksum) {
					// TODO call free function here
					free(m_aux);
					printf("Found incorrect checksum, dropping IP packet\n");
					break;
				}
				for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i){
					// If the packet has its destination address one of the router's interfaces
					// Respond only to ICMP ehco requests

					if (ntohl(ip_hdr->daddr ) == router_interfaces[i] && ip_hdr->protocol == IPPROTO_ICMP) {
						printf("Found ICMP packet for router\n");
						// If the destination is the router, respond only to icmp echo requests
						// else drop the packet
						struct icmphdr *icmp_hdr = (struct icmphdr *)(m_aux->payload + sizeof(struct ether_header) + sizeof(struct iphdr));
						// Respond with reply
						if (icmp_hdr->type == ICMP_ECHO) {
							// TODO - implement ICMP REPLY
							printf("Found ICMP echo request\n");
							// Create a buffer for the ICMP echo reply packet
							struct ether_header *eth_hdr_icmp = (struct ether_header *)m_aux->payload;
							struct iphdr *ip_hdr_icmp = (struct iphdr *)(m_aux->payload + sizeof(struct ether_header));
							struct icmphdr *icmp_hdr_reply = (struct icmphdr *)(m_aux->payload + sizeof(struct ether_header) + sizeof(struct iphdr));

							// Modify the ethernet SRC and DST addresses
							uint8_t mac_aux_interface[ETH_ALEN];
							get_interface_mac(m_aux->interface, mac_aux_interface);
							memcpy(eth_hdr_icmp->ether_dhost, eth_hdr_icmp->ether_shost, ETH_ALEN);
							memcpy(eth_hdr_icmp->ether_shost, mac_aux_interface, ETH_ALEN);

							// Modify IP SRC and DST
							uint32_t aux = ip_hdr->daddr;
							ip_hdr_icmp->daddr = ip_hdr->saddr;
							ip_hdr_icmp->saddr = aux;
							ip_hdr_icmp->check = 0;
							ip_hdr_icmp->ttl -= 1;

							// Modify ICMP type and code to indicate echo reply
							icmp_hdr_reply->type = ICMP_ECHOREPLY;  // Echo reply type
							icmp_hdr_reply->code = 0;  // Code for echo reply
							icmp_hdr_reply->checksum = 0;
							
							// Calculate the ICMP header checksum and IP
							uint16_t ip_checksum_recalculated = ip_checksum2(ip_hdr_icmp, ip_hdr_icmp->ihl<<2);
							// ip_hdr_icmp->check = htons(ip_checksum(ip_hdr_icmp));
							ip_hdr_icmp->check = ip_checksum_recalculated;

							unsigned char * p_total = (unsigned char *)m_aux->payload + sizeof(struct ether_header) + sizeof(struct iphdr);
							uint16_t icmp_checksum_recalculated = ip_checksum2((uint16_t *)p_total, sizeof(struct icmphdr)+ 48 + 8);
							
							// icmp_hdr_reply->checksum = htons(icmp_checksum(m_aux, icmp_data_len));	
							icmp_hdr_reply->checksum = icmp_checksum_recalculated;

							// Send packet
							send_packet(m_aux->interface, m_aux);
							printf("ICMP echo reply sent\n");
							free(m_aux);

							var=1;
							break;
						} else {
							// Packet is for one of router's interfaces but not an ICMP ECHO request, so drop packet
							var = 1;
							free(m_aux);
							break;
						}
					}	
				}
				if (var)
					break;

				// If the IP packet is not for one of the router's interfaces, forward the packet
				// TODO - Forward packet
				ip_hdr->ttl--;
				if (ip_hdr->ttl <= 1) {
					// if TTL <= 1, drop packet, send ICMP "Time Exceeded" message back to the sender
					// TODO
					printf("The ttl is less than 1\n");
				}
				// Now find a match in the routing table
				printf("The destination address that we need to route to is: \n");
				printIPAddress(ip_hdr->daddr);
				struct route_table_entry *p = get_best_route(ntohl(ip_hdr->daddr));
				// No next hop has been found
				if (p == NULL) {
					// TODO - send ICMP destination unreachable
					printf("No route has been found\n");
					break;
					free(m_aux);
				}
				printf("Route found: \n");
				printIPAddress(p->next_hop);

				// Now we need to update the src and dst MAC addresses of the packet
				
				uint8_t mac_aux_interface[ETH_ALEN];

				// Get the MAC of router's interface and set it
				// Update the SRC MAC to be the router's interface MAC
				get_interface_mac(m_aux->interface, mac_aux_interface);
				memcpy(eth_hdr->ether_shost, mac_aux_interface, ETH_ALEN);

				// Now need to find next hop's MAC address
				// printf("p->next hop is: \n");
				// printIPAddress(p->next_hop);
				struct arp_entry *arp_table_aux = get_arp_entry(p->next_hop);

				// If we don't find a corresponding IP address mapped to a MAC address
				// We have to send an ARP request asking for next hop's MAC address
				if(arp_table_aux == NULL) {
					// Store our packet to be sent in a queue, send the ARP request, 

					// Create a buffer for the ARP request packet
					packet *reply_pkt = (packet *)malloc(sizeof(packet));

					// Construct the Ethernet header
					struct ether_header *eth_hdr_request = (struct ether_header *)reply_pkt->payload;
					memcpy(eth_hdr_request->ether_shost, mac_aux_interface, ETH_ALEN);

					uint8_t broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
					memcpy(eth_hdr_request->ether_dhost, broadcast_mac, ETH_ALEN);
					eth_hdr_request->ether_type = htons(ETHERTYPE_ARP);

					// Construct the ARP header
					struct arphdr *arp_hdr_request = (struct arphdr *)(reply_pkt->payload + sizeof(struct ether_header));
					arp_hdr_request->ar_hrd = htons(ARPHRD_ETHER);
					arp_hdr_request->ar_pro = htons(ETHERTYPE_IP);
					arp_hdr_request->ar_hln = ETH_ALEN;
					arp_hdr_request->ar_pln = sizeof(in_addr_t);
					arp_hdr_request->ar_op = htons(ARPOP_REQUEST);

					// Construct the ARP request
					struct arp_request *arp_request_packet = (struct arp_request *)(reply_pkt->payload + sizeof(struct ether_header) + sizeof(struct arphdr));
					// Sender hardware address, Sender IP address, target hardware address, target IP address
					memcpy(arp_request_packet->ar_sha, mac_aux_interface, ETH_ALEN);
					char* interface_ip_str = get_interface_ip(m_aux->interface);
					uint32_t interface_ip = inet_addr(interface_ip_str);
					arp_request_packet->ar_sip = interface_ip;
					// memcpy(arp_request_packet->ar_sip, &interface_ip, sizeof(uint32_t));
					memcpy(arp_request_packet->ar_tha, broadcast_mac, ETH_ALEN);
					// arp_request_packet->ar_tip = htonl(arp_request_packet->ar_sip);
					arp_request_packet->ar_tip = p->next_hop;
					// memcpy(arp_request_packet->ar_tip, p->next_hop, sizeof(uint32_t));

					// Now construct a new packet and send it
					// Copy the Ethernet header
					reply_pkt->len = sizeof(struct ether_header);

					// Increment the length by the size of the ARP header
					reply_pkt->len += sizeof(struct arphdr);

					// Copy the ARP header
					// memcpy(toSend.payload + sizeof(struct ether_header), arp_request_buffer + sizeof(struct ether_header), sizeof(struct arphdr));

					// Increment the length by the size of the ARP request
					reply_pkt->len += sizeof(struct arp_request);

					// Copy the ARP request
					// memcpy(toSend.payload + sizeof(struct ether_header) + sizeof(struct arphdr), arp_request_buffer + sizeof(struct ether_header) + sizeof(struct arphdr), sizeof(struct arp_request));

					// Set the interface of the packet
					// We get this from the get_best_route() function
					reply_pkt->interface = p->interface;
					printf("p->interface is: %d\n", p->interface);

					// We need to also add the packet that needs to be forwarded in a hash table, and send it later
					// when we receive an arp reply
					add_packet_to_hashtable(arp_request_packet->ar_tip, m_aux);


					// Send the ARP request packet as broadcast
					send_packet(p->interface, reply_pkt);
					printf("Successfully sent ARP request\n");
					// free(m_aux);
			
				} else {
					// We found an ARP entry for the next hop, so immediately forward the packet to destination next hop
					// We already changed the source MAC address, now we need to change the destination MAC address from
					// the arp table associated with the IP
					// memcpy(eth_hdr->ether_dhost, arp_table_aux->mac, ETH_ALEN);
					memcpy(eth_hdr->ether_dhost, arp_table_aux->mac, ETH_ALEN);
					// Update the checksum
					uint16_t computed_checksum = ip_checksum2(ip_hdr, sizeof(struct iphdr));
					ip_hdr->check = computed_checksum;
					// Send the packet
					send_packet(p->interface, m_aux);
					printf("Successfully routed packet\n");

				}


				break;
			}
			

			
			case ETHERTYPE_ARP: {
				// Handle ARP packet
				// printf("Handling ARP packet\n");
				struct arphdr *arp_hdr = (struct arphdr *)(m_aux->payload + sizeof(struct ether_header));
				struct arp_request *arp_req = (struct arp_request *)(m_aux->payload + sizeof(struct ether_header) + sizeof(struct arphdr));
				for (int i = 0; i < ROUTER_NUM_INTERFACES; ++i){
					// printf("Main thread - router_interfaces[%d]: %u\n", i, router_interfaces[i]);
					// printf("Main thread - arp_req->ar_tip: %u\n", ntohl(arp_req->ar_tip));
					

					if(ntohl(arp_req->ar_tip )== router_interfaces[i]){
            			// printf("Found ARP packet matching the %d interface\n", i);
						// printf("Now preparing to send ARP reply\n");
						// If we have an ARP request for one of the router's interfaces
						// Respond with ARP reply with the corresponding MAC address
						if (ntohs(arp_hdr ->ar_op) == ARPOP_REQUEST) {
							
							// Create a buffer for the ARP reply packet
							// printf("Found an ARP request\n");
							unsigned char arp_reply_buffer[ETH_FRAME_LEN];
							packet toSend;

							// Construct the Ethernet header
							// Copy source address of the incoming packet to desti of the outgoing
							struct ether_header *eth_hdr_reply = (struct ether_header *)arp_reply_buffer;
							memcpy(eth_hdr_reply->ether_dhost, eth_hdr->ether_shost, ETH_ALEN);

							// Get the router interface MAC address
							uint8_t * tmp_mac = malloc(sizeof(uint8_t));
							get_interface_mac(i, tmp_mac);

							memcpy(eth_hdr_reply->ether_shost, tmp_mac, ETH_ALEN);
							eth_hdr_reply->ether_type = htons(ETHERTYPE_ARP);

							// Construct the ARP header
							struct arphdr *arp_hdr_reply = (struct arphdr *)(arp_reply_buffer + sizeof(struct ether_header));
							arp_hdr_reply->ar_hrd = htons(ARPHRD_ETHER);
							arp_hdr_reply->ar_pro = htons(ETHERTYPE_IP);
							arp_hdr_reply->ar_hln = ETH_ALEN;
							arp_hdr_reply->ar_pln = sizeof(in_addr_t);
							arp_hdr_reply->ar_op = htons(ARPOP_REPLY);


							// Construct the ARP request
							struct arp_request *arp_reply = (struct arp_request *)(arp_reply_buffer + sizeof(struct ether_header) + sizeof(struct arphdr));
							// Sender hardware address, Sender IP address, target hardware address, target IP address
							memcpy(arp_reply->ar_sha, tmp_mac, ETH_ALEN);
							// memcpy(arp_reply->ar_sip, router_interfaces[i], sizeof(uint32_t));
							arp_reply->ar_sip = htonl(router_interfaces[i]);
							memcpy(arp_reply->ar_tha, arp_req->ar_sha, ETH_ALEN);
							arp_reply->ar_tip = htonl(arp_req->ar_sip);
							// memcpy(arp_reply->ar_tip, arp_req->ar_sip, sizeof(uint32_t));


							// Now construct a new packet and send it
							// Copy the Ethernet header
							memcpy(toSend.payload, arp_reply_buffer, sizeof(struct ether_header));
							toSend.len = sizeof(struct ether_header);

							// Increment the length by the size of the ARP header
							toSend.len += sizeof(struct arphdr);

							// Copy the ARP header
							memcpy(toSend.payload + sizeof(struct ether_header), arp_reply_buffer + sizeof(struct ether_header), sizeof(struct arphdr));

							// Increment the length by the size of the ARP request
							toSend.len += sizeof(struct arp_request);

							// Copy the ARP request
							memcpy(toSend.payload + sizeof(struct ether_header) + sizeof(struct arphdr), arp_reply_buffer + sizeof(struct ether_header) + sizeof(struct arphdr), sizeof(struct arp_request));

							// Set the interface of the packet
							toSend.interface = i;
							
							
							

							// Send the ARP reply packet back to the source IP address
							send_packet(i, &toSend);
							printf("Successfully sent ARP reply\n");
							free(m_aux);
							free(tmp_mac);
							// TODO call free function here


						} else if (ntohs(arp_hdr ->ar_op) == ARPOP_REPLY) {
							// TODO - update ARP table
							printf("Found ARP reply!\n");

							// Write ARP table if empty
							int found = 0;
							for (int i = 0; i < arp_table_len; i++) {
								if (arp_req->ar_sip == arp_table[i].ip) {
									found = 1;
									break;
								}
							}

							// If IP address not found, write it to the ARP table
							if (!found) {
								write_arp_table(arp_req->ar_sip, arp_req->ar_sha);
								printf("Succseffully wrote arp table\n");
								parse_arp_table();
							}

							// We go the arp reply, so now forward any more packets that need to be forwarded from the hashtable
							packet *toSend = get_packet_from_hashtable(arp_req->ar_sip);
							if (toSend != NULL) {
								// We found the ARP reply associated with our IP packet from the hash table
								// Now update MAC addresses
								struct ether_header *ip_packet = (struct ether_header *)toSend->payload;
								memcpy(ip_packet->ether_dhost, arp_req->ar_sha, ETH_ALEN);
								send_packet(toSend->interface, toSend);
								remove_packet_from_hashtable(arp_req->ar_sip);
							} else {
								printf("Fatal error: Trying to get a non existent entry from the hashtable\n");
							}


						}

					}
				}
				
				break;
			}
			// Add more cases for other protocols as needed

			default:
				printf("Protocol not supported!\n");
			// Handle unknown or unsupported protocol
			break;
		}




	}
}
