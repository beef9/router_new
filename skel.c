#include "skel.h"
#include <errno.h>
#define MAX_ARP_ENTRIES 100

extern int interfaces[ROUTER_NUM_INTERFACES];

extern int rtable_size;
extern int arp_table_len;

extern struct arp_entry *arp_table;
extern struct route_table_entry *rtable;
extern struct hashtable_entry *hashtable;

void printIPAddress(uint32_t ip) {
    printf("%d.%d.%d.%d\n",
           (ip >> 24) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 8) & 0xFF,
           ip & 0xFF);
}

struct route_table_entry *get_best_route(uint32_t dest_ip) {
    int low = 0;
    int high = rtable_size - 1;
    struct route_table_entry *best_match = NULL;
    uint32_t longest_prefix = 0;

    // Perform binary search to find a potential match
    while (low <= high) {
        int mid = (low + high) / 2;
        uint32_t to_verify = dest_ip & ntohl(rtable[mid].mask);

        if (to_verify == ntohl(rtable[mid].prefix)) {
            // Exact match found, update the best match and continue searching for longer matches
            best_match = &rtable[mid];
            longest_prefix = ntohl(rtable[mid].mask);
            break;
        } else if (to_verify < ntohl(rtable[mid].prefix)) {
            // Check lower half of the table
            high = mid - 1;
        } else {
            // Check upper half of the table
            low = mid + 1;
        }
    }

    // Traverse linearly from the potential match to find the longest prefix match
    for (int i = low; i < rtable_size; i++) {
        uint32_t prefix_masked = dest_ip & ntohl(rtable[i].mask);

        if (prefix_masked == ntohl(rtable[i].prefix) && ntohl(rtable[i].mask) > longest_prefix) {
            best_match = &rtable[i];
            longest_prefix = ntohl(rtable[i].mask);
        }
    }

    return best_match;
}


struct arp_entry *get_arp_entry(__u32 ip) {
    /* TODO 2: Implement */
    for (int i = 0; i < arp_table_len; i++){
        if(ip == arp_table[i].ip){
            fprintf(stderr, "FOUND GOOD ARP ENTRY\n");
            
            unsigned char octet2[4]  = {0,0,0,0};
            for (int j=0; j<4; j++)
            {
                octet2[j] = ( ip >> (j*8) ) & 0xFF;
            }

            fprintf(stderr, "%d. ", arp_table_len);
            fprintf(stderr, "GOOD Arp entry is: %d.%d.%d.%d\n",octet2[0],octet2[1],octet2[2],octet2[3]);
            
            
            return &arp_table[i];
        }
    }
 
    return NULL;
}

int socket_send_message(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	int ret;
	ret = write(sockfd, m->payload, m->len);
        printf("scokfd is: %d\n", sockfd);
        printf("payload is: \n");
        for(int i = 0; i < m->len; i++){
            printf("%c", m->payload[i]);
        }
        printf("\n");
        //printf("message payload is: %s\n", m->payload);
        printf("message len is: %d\n", m->len);
        if(ret == -1){
            printf("wirte error()!:  %s\n", strerror(errno));
           
            DIE(ret == -1, "write");
        }
	
	return ret;
}


void parse_arp_table() 
{
 FILE *f;
    fprintf(stderr, "Parsing ARP table\n");
    f = fopen("arp_table.txt", "r");
    DIE(f == NULL, "Failed to open arp_table.txt");
    char line[100];
    int i = arp_table_len; // Start from the current length of arp_table[]
    

	// This condition allows the loop to read lines from the file until either all the lines are processed
	// or the maximum number of ARP entries is reached.
    while (fgets(line, sizeof(line), f) && i < MAX_ARP_ENTRIES) {
        char ip_str[50], mac_str[50];
        sscanf(line, "%s %s", ip_str, mac_str);
        
        // Check if the IP address already exists in arp_table[]
        int exists = 0;
        for (int j = 0; j < i; j++) {
            if (arp_table[j].ip == inet_addr(ip_str)) {
                exists = 1;
                break;
            }
        }
        
        if (!exists) {
            fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
            arp_table[i].ip = inet_addr(ip_str);
            int rc = hwaddr_aton(mac_str, arp_table[i].mac);
            DIE(rc < 0, "invalid MAC");
            i++;
        }
    }
    
    arp_table_len = i;
    fclose(f);
}

int read_rtable(struct route_table_entry *rtable){
    FILE *f;
    fprintf(stderr, "Parsing ROUTING table\n");
    f = fopen("rtable.txt", "r");
    DIE(f == NULL, "Failed to open rtable.txt");
    char line[100];
    int i = 0;
    for(i = 0; fgets(line, sizeof(line), f); i++) {
            char prefix_str[50], next_hop_str[50], mask_str[50];
            int interface=0;
            sscanf(line, "%s %s %s %d", prefix_str, next_hop_str, mask_str, &interface);
            //fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
            rtable[i].prefix = inet_addr(prefix_str);
            rtable[i].next_hop = inet_addr(next_hop_str);
            rtable[i].mask = inet_addr(mask_str);
            rtable[i].interface = interface;
            //int rc = hwaddr_aton(mac_str, arp_table[i].mac);
            //DIE(rc < 0, "invalid MAC");
    }
    // *rtable_size = i;
    fclose(f);
    return i;
}

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	int ret;
	ret = write(interfaces[sockfd], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

void write_arp_table(__u32 ip_addr, unsigned char mac_addr[ETH_ALEN])
{
    FILE *file = fopen("arp_table.txt", "a"); // Open the file in "append" mode

    if (file) {
        fprintf(file, "%d.%d.%d.%d", ((unsigned char *)&ip_addr)[0], ((unsigned char *)&ip_addr)[1],
                ((unsigned char *)&ip_addr)[2], ((unsigned char *)&ip_addr)[3]);

        fprintf(file, " %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_addr[0], mac_addr[1], mac_addr[2],
                mac_addr[3], mac_addr[4], mac_addr[5]);

        fclose(file);
    } else {
        file = fopen("arp_table.txt", "w"); // Create the file if it doesn't exist

        if (file) {
            fprintf(file, "%d.%d.%d.%d", ((unsigned char *)&ip_addr)[0], ((unsigned char *)&ip_addr)[1],
                    ((unsigned char *)&ip_addr)[2], ((unsigned char *)&ip_addr)[3]);

            fprintf(file, " %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac_addr[0], mac_addr[1], mac_addr[2],
                    mac_addr[3], mac_addr[4], mac_addr[5]);

            fclose(file);
        } else {
            printf("Failed to create file: arp_table.txt\n");
        }
    }
}


int get_packet(packet *m) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

void add_packet_to_hashtable(uint32_t ip, packet *pkt) {
    struct hashtable_entry *entry;
    HASH_FIND_INT(hashtable, &ip, entry);  // Check if IP already exists in the hash table
    if (entry == NULL) {
        entry = (struct hashtable_entry *)malloc(sizeof(struct hashtable_entry));  // Create a new entry if IP doesn't exist
        entry->ip = ip;
		entry->value = pkt;
        HASH_ADD_INT(hashtable, ip, entry);
    }
	// Found
}      

void remove_packet_from_hashtable(uint32_t ip) {
    struct hashtable_entry *entry;
    HASH_FIND_INT(hashtable, &ip, entry);  // Find the entry with the specified IP address
    if (entry != NULL) {
        HASH_DEL(hashtable, entry);  // Remove the entry from the hash table
        free(entry);  // Free the memory allocated for the entry
    }
}

void free_hashtable() {
    struct hashtable_entry *entry, *tmp;
    HASH_ITER(hh, hashtable, entry, tmp) {
        HASH_DEL(hashtable, entry);
        free(entry);
    }
}

packet *get_packet_from_hashtable(uint32_t ip) {
    struct hashtable_entry *entry;
    HASH_FIND_INT(hashtable, &ip, entry);  // Find the entry with the specified IP address
    if (entry != NULL) {
        return entry->value;  // Return the associated packet
    }
    return NULL;  // IP address not found in the hash table
}                                                                                                                

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	
}

void init()
{
	int s0 = get_sock("r-0");
	int s1 = get_sock("r-1");
	int s2 = get_sock("r-2");
	int s3 = get_sock("r-3");
	interfaces[0] = s0;
	interfaces[1] = s1;
	interfaces[2] = s2;
	interfaces[3] = s3;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}
/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}
