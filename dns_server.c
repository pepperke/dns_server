#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <regex.h>

#include "dns_server.h"
#include "dns_hosts.h"
#include "hash_table.h"

// Global variables to be able to clear them correctly 
// after receiving Ctrl-C
HashTable *ht;
int server_socket;

/* Handler function to catch signal */
void sigint_handler(int s) {
    printf("\nExiting...\n");
    free_hashtable(ht);
    close(server_socket);
    exit(0);
}

int main(int argc, char *argv[]) {
    // Create hast table to store hosts
    ht = create_table(1023);

    if (argc > 1) {
        if (argc != 2) {
            printf("Too many arguments. Usage ./dns_server [filename]\n");
            exit(1);
        }
        read_hosts(ht, argv[1]);
    }
    else {
        read_hosts(ht, "hosts"); // No arguments given
    }

    // Define handler to catch Ctrl-C
    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = sigint_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);


    // Create UDP server on port 10053
    struct addrinfo *bind_addr, hints;
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(0, "10053", &hints, &bind_addr)) {
        perror("Failed to get address info");
        exit(1);
    }

    server_socket = socket(bind_addr->ai_family, bind_addr->ai_socktype, 
                bind_addr->ai_protocol);
    
    if (server_socket < 0) {
        perror("Failed to create server socket");       
        exit(1);
    }

    if (bind(server_socket, bind_addr->ai_addr, bind_addr->ai_addrlen) < 0) {
        perror("Failed to bind");
        exit(1);
    }
    freeaddrinfo(bind_addr);

    printf("Server is started, waiting for packets\n");

    char command[300]; // Buffer for user commands

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100 * 1000; // 100 ms

    fd_set reads;

    while (1) {
        FD_ZERO(&reads);
        FD_SET(server_socket, &reads);
        FD_SET(0, &reads);
        if (select(server_socket+1, &reads, 0, 0, &timeout) < 0) {
            perror("Error");
            exit(1);
        }
        if (FD_ISSET(server_socket, &reads)) {
            process_query();
        }
        if (FD_ISSET(0, &reads)) { // Got query on port
            fgets(command, sizeof(command), stdin);
            process_user_command(command);
        }
    }

    return 0;
}

void read_ipv4(const unsigned char packet_ptr[], unsigned char *address) {
    sprintf(address, "%u.%u.%u.%u", packet_ptr[0], packet_ptr[1], 
            packet_ptr[2], packet_ptr[3]);
}

const char * read_qname(const char packet_ptr[], const char packet_start[], char domain[]) {
    const char *msg_ptr = packet_ptr;
    const char *saved_ptr = packet_ptr;
    char len;
    int offset = 0;

    domain[0] = '\0';

    while (*msg_ptr) {
        if ((*msg_ptr & 0xC0) == 0xC0) {
            if (saved_ptr == packet_ptr){
                saved_ptr = msg_ptr;
            }
            offset = ((*msg_ptr & 0x3F) << 8) | msg_ptr[1];
            msg_ptr = packet_start + offset;
        } else {
            len = *msg_ptr++;
            strncat(domain, msg_ptr, len);
            msg_ptr += len;
            if (*msg_ptr != 0) {
                strcat(domain, ".");
            }
        }
    }
    if (offset) {
        return saved_ptr + 2;
    } else {
        return msg_ptr + 1;
    }
}

const char * read_header(const char packet[], struct dns_header *header) {
    const unsigned char *packet_ptr = packet;

    header->id = (packet_ptr[0] << 8) | packet_ptr[1];
    packet_ptr += 2;

    header->qr = (*packet_ptr & 0x80) >> 7;
    header->opcode = (*packet_ptr & 0x78) >> 3;
    header->aa = (*packet_ptr & 0x04) >> 2;
    header->tc = (*packet_ptr & 0x02) >> 1;
    header->rd = (*packet_ptr & 0x01);
    packet_ptr++;

    header->ra = (*packet_ptr & 0x80) >> 7;
    header->z  = (*packet_ptr & 0x07) >> 4;
    if (header->qr) {
        header->rcode = (*packet_ptr & 0x0F);
    }
    packet_ptr++;

    header->qdcount = (*packet_ptr++ << 8) | *packet_ptr++;
    header->ancount = (*packet_ptr++ << 8) | *packet_ptr++;
    header->nscount = (*packet_ptr++ << 8) | *packet_ptr++;
    header->arcount = (*packet_ptr++ << 8) | *packet_ptr++;
    return packet_ptr;
}

const char * read_questions(const char packet_ptr[], const char packet_start[],
            int qdcount, struct resource_record *questions) {
    int rtype, rclass;

    for (int i = 0; i < qdcount; i++) {
        packet_ptr = read_qname(packet_ptr, packet_start, questions->domain);

        rtype = (packet_ptr[0] << 8) | packet_ptr[1];
        switch (rtype) {
            case 1: questions->rtype = A; break;
            default: questions->rtype = type_unknown; break;
        }
        packet_ptr += 2;

        rclass = (packet_ptr[0] << 8) | packet_ptr[1];
        switch (rclass) {
            case 1: questions->rclass = IN; break;
            default: questions->rclass = class_unknown; break;
        }
        packet_ptr += 2;

        if (i + 1 < qdcount) {
            struct resource_record *questions_next = malloc(sizeof(struct resource_record));
            questions->next = questions_next;
            questions = questions_next;
        }
        return packet_ptr;
    }
}

const char * read_records(const char packet_ptr[], const char packet_start[], 
            int rcount, struct resource_record *records) {
    int rtype, rclass;

    for (int i = 0; i < rcount; i++) {
        packet_ptr = read_qname(packet_ptr, packet_start, records->domain);

        rtype = (packet_ptr[0] << 8) | packet_ptr[1];
        switch (rtype) {
            case 1: records->rtype = A; break;
            default: records->rtype = type_unknown; break;
        }
        packet_ptr += 2;

        rclass = (packet_ptr[0] << 8) | packet_ptr[1];
        switch (rclass) {
            case 1: records->rclass = IN; break;
            default: records->rclass = class_unknown; break;
        }
        packet_ptr += 2;

        records->ttl = (packet_ptr[0] << 24) 
            | (packet_ptr[1] << 16) 
            | (packet_ptr[2] << 8) 
            | (packet_ptr[3]); 

        packet_ptr += 4;

        records->rdlen = (packet_ptr[0] << 8) | packet_ptr[1];
        packet_ptr += 2;

        if (records->rtype == A) {
            records->data = malloc(sizeof(struct in_addr));
            read_ipv4(packet_ptr, records->data);
            packet_ptr += 4;
        }

        if (i + 1 < rcount) {
            struct resource_record *records_next = malloc(sizeof(struct resource_record));
            records->next = records_next;
            records = records_next;
        }
    }
    return packet_ptr;
}

void read_packet(const char packet[], struct dns_packet *dns_packet) {
    const char *packet_ptr = packet;

    dns_packet->questions = malloc(sizeof(struct resource_record));
    dns_packet->answers = malloc(sizeof(struct resource_record));
    dns_packet->authorities = malloc(sizeof(struct resource_record));
    dns_packet->additional = malloc(sizeof(struct resource_record));

    packet_ptr = read_header(packet_ptr, &(dns_packet->header));

    if (dns_packet->header.qdcount) {
        packet_ptr = read_questions(packet_ptr, packet, dns_packet->header.qdcount,
                    dns_packet->questions);
    }

    if (dns_packet->header.ancount) {
        packet_ptr = read_records(packet_ptr, packet, dns_packet->header.ancount,
                    dns_packet->answers);
    }

    if (dns_packet->header.nscount) {
        packet_ptr = read_records(packet_ptr, packet, dns_packet->header.nscount,
                    dns_packet->authorities);
    }

    if (dns_packet->header.arcount) {
        packet_ptr = read_records(packet_ptr, packet, dns_packet->header.arcount,
                    dns_packet->additional);
    }
}

char * write_ipv4(unsigned char *packet_ptr, unsigned char address[]) {
    unsigned char *octets;
    octets = strtok(address, ".");

    for (int i = 0; i < 3; i++) {
        *packet_ptr++ = atoi(octets);
        octets = strtok(NULL, ".");
    }
    *packet_ptr++ = atoi(octets);
    return packet_ptr;
}

char * write_qname(unsigned char *packet_ptr, const char *domain) {
    unsigned char *len;

    while (*domain) {
        len = packet_ptr++;
        while (*domain != '.' && *domain) {
            *packet_ptr++ = *domain++;
        }
        *len = packet_ptr - len - 1;

        if (*domain) {
            domain++;  
        } else {
            break;
        }
    }
    *packet_ptr++ = 0;
    return packet_ptr;
}

char * write_header(char packet[], const struct dns_packet *dns_packet) {
    char *packet_ptr = packet;
    struct dns_header header = dns_packet->header;

    *packet_ptr++ = header.id >> 8;
    *packet_ptr++ = header.id & 0xFF;

    *packet_ptr++ = (header.qr << 7)
                  | (header.opcode << 3)
                  | (header.aa << 2)
                  | (header.tc << 1)
                  | (header.rd);

    *packet_ptr++ = (header.ra << 7)
                  | (header.z << 4)
                  | (header.rcode);

    *packet_ptr++ = header.qdcount >> 8;
    *packet_ptr++ = header.qdcount & 0xFF;

    *packet_ptr++ = header.ancount >> 8;
    *packet_ptr++ = header.ancount & 0xFF;

    *packet_ptr++ = header.nscount >> 8;
    *packet_ptr++ = header.nscount & 0xFF;

    *packet_ptr++ = header.arcount >> 8;
    *packet_ptr++ = header.arcount & 0xFF;
    return packet_ptr;
}

char * write_questions(char packet[], int qdcount, const struct resource_record *questions) {
    char *packet_ptr = packet;

    for (int i = 0; i < qdcount; i++) {
        packet_ptr = write_qname(packet_ptr, questions->domain);
        *packet_ptr++ = questions->rtype >> 8;
        *packet_ptr++ = questions->rtype & 0xFF;

        *packet_ptr++ = questions->rclass >> 8;
        *packet_ptr++ = questions->rclass & 0xFF;

        if (questions->next)
            questions = questions->next;
    }
    return packet_ptr;
}

char * write_records(char packet[], int rcount, const struct resource_record *records) {
    char *packet_ptr = packet;

    for (int i = 0; i < rcount; i++) {
        packet_ptr = write_qname(packet_ptr, records->domain);
        *packet_ptr++ = records->rtype >> 8;
        *packet_ptr++ = records->rtype & 0xFF;

        *packet_ptr++ = records->rclass >> 8;
        *packet_ptr++ = records->rclass & 0xFF;

        *packet_ptr++ = records->ttl >> 24;
        *packet_ptr++ = records->ttl >> 16;       
        *packet_ptr++ = records->ttl >> 8;       
        *packet_ptr++ = records->ttl & 0xFF;       

        *packet_ptr++ = records->rdlen >> 8;
        *packet_ptr++ = records->rdlen & 0xFF;

        if (records->rtype == A) {
            packet_ptr = write_ipv4(packet_ptr, records->data);
        }

        if (records->next)
            records = records->next;
    }
    return packet_ptr;
}

int write_packet(char packet[], const struct dns_packet *dns_packet) {
    char *packet_ptr = packet;

    packet_ptr = write_header(packet_ptr, dns_packet);

    if (dns_packet->header.qdcount) {
        packet_ptr = write_questions(packet_ptr, dns_packet->header.qdcount, 
                dns_packet->questions);
    }

    if (dns_packet->header.ancount) {
        packet_ptr = write_records(packet_ptr, dns_packet->header.ancount, 
                dns_packet->answers);
    }

    if (dns_packet->header.nscount) {
        packet_ptr = write_records(packet_ptr, dns_packet->header.nscount, 
                dns_packet->authorities);
    }

    if (dns_packet->header.arcount) {
        packet_ptr = write_records(packet_ptr, dns_packet->header.arcount, 
                dns_packet->additional);
    }
    return packet_ptr - packet;
}

void free_dns_packet(struct dns_packet *dns_packet) {
    struct dns_header header = dns_packet->header;

    struct resource_record *record;
    struct resource_record *old_record;

    record = dns_packet->questions;
    for (int i = 0; i < header.qdcount; i++) {
        old_record = record;
        record = record->next;
        free(old_record);
    }

    record = dns_packet->answers;
    for (int i = 0; i < header.ancount; i++) {
        old_record = record;
        record = record->next;
        free(old_record);
    }

    record = dns_packet->authorities;
    for (int i = 0; i < header.nscount; i++) {
        old_record = record;
        record = record->next;
        free(old_record);
    }

    record = dns_packet->additional;
    for (int i = 0; i < header.arcount; i++) {
        old_record = record;
        record = record->next;
        free(old_record);
    }
}

void process_query() {
    struct dns_packet dns_packet;

    unsigned char query_buff[512];

    struct sockaddr_storage client_address; // Create a storage for client address
    socklen_t client_len = sizeof(client_address);

    int bytes_recieved = recvfrom(server_socket, query_buff, sizeof(query_buff), 0,
                (struct sockaddr *)&client_address, &client_len);

    if (bytes_recieved > 0) {
        read_packet(query_buff, &dns_packet);
    }
    else {
        return;
    }
    char client_address_buff[40]; // So that both IPv4 and IPv6 address could fit 
    char port[5];

    getnameinfo((struct sockaddr *)&client_address, client_len, 
                client_address_buff, sizeof(client_address_buff), 
                port, sizeof(port), NI_NUMERICSERV);

    printf("Got query from %s:%s\n", client_address_buff, port);

    LinkedList *head = ht_search(ht, dns_packet.questions->domain); // Can serve only one Question, 
                                                                    // so read only first of them
    
    dns_packet.answers = malloc(sizeof(struct resource_record));
    struct resource_record *first_answer = dns_packet.answers;

    int answer_count = 0;
    while (head) {
        answer_count++;
        
        strcpy(dns_packet.answers->domain, dns_packet.questions->domain);
        dns_packet.answers->rtype = A;
        dns_packet.answers->rclass = IN;
        dns_packet.answers->ttl = 60;
        dns_packet.answers->rdlen = 4;

        dns_packet.answers->data = malloc(sizeof(struct in_addr));
        strcpy(dns_packet.answers->data, head->item->value);

        head = head->next;
        if (head) {
            dns_packet.answers->next = malloc(sizeof(struct resource_record));
            dns_packet.answers = dns_packet.answers->next;
        }
    }
    dns_packet.answers = first_answer;

    dns_packet.header.ancount = answer_count;

    if (dns_packet.header.opcode != 0) {
        printf("Can only serve standard queries\n");
        return;
    }

    dns_packet.header.qr = 1; // Response
    dns_packet.header.ra = 0; // No recursion

    if (!answer_count) {
        dns_packet.header.rcode = NAME_ERROR; // No such domain in hosts
    }
    else {
        dns_packet.header.rcode = NOERROR;    // Ok
    }

    int packet_size = write_packet(query_buff, &dns_packet);

    sendto(server_socket, query_buff, packet_size, 0, 
                (struct sockaddr *)&client_address, client_len);
                
    printf("Sent %d bytes for domain %s\n", packet_size, dns_packet.questions->domain);

    free_dns_packet(&dns_packet);
}

void process_user_command(char command[]) {
    if (!command) {
        return;
    }
    // 10 for command itself (+spaces), 255 for URL (by RFC), 15 for IP)
    if (strlen(command) > 10 + 255 + 15) {
        printf("Too long command\n");
        // Clear stdin in case command was too long to fit in one call to fgets
        fgets(command, strlen(command), stdin); 
        return;
    }
                                         
    char *token = strtok(command, " ");
    if (strcmp(token, "host") != 0) {
        printf("Command is not supported\n");
        return;     // Do not support commands that don't start with "host"
    }

    token = strtok(NULL, " \n");
    if (strcmp(token, "print") == 0) {
        print_hosts(ht);
    }
    else if (strcmp(token, "add") == 0) {
        char *domain = strtok(NULL, " \n");     // Domain
        char *ip = strtok(NULL, " \n");         // IP
        
        if (!is_valid_domain(domain)) {
            printf("Wrong domain format\n");
            return;
        }
        if (!is_valid_ip(ip)) {
            printf("Wrong ip format\n");
            return;
        }

        add_host(ht, domain, ip);
    } 
    else if (strcmp(token, "delete") == 0) {
        token = strtok(NULL, " \n");            // Domain

        if (!token) {
            printf("Wrong syntax\n");
            return;
        }
        delete_host(ht, token);
    }
    else if (strcmp(token, "save") == 0) {
        token = strtok(NULL, " \n");            // File name
        
        if (!token) {
            printf("Wrong syntax\n");
            return;
        }
        write_hosts(ht, token);
    } 
    else {
        printf("Command is not supported\n");
        return;
    }
}

int is_valid_ip_part(char part[]) {
    int n = strlen(part); 

    if (n > 3) 
        return 0; 

    for (int i = 0; i < n; i++) {
        if ((part[i] >= '0' && part[i] <= '9') == 0) {
            return 0;
        }
    }

    int x = atoi(part); 
    return (x >= 0 && x <= 255); 
}

int is_valid_ip(char ip[]) {
    if (!ip) {
        return 0; 
    } 
    int i, num, dots = 0; 
    int len = strlen(ip); 
    int count = 0; 

    for (int i = 0; i < len; i++) {
        if (ip[i] == '.') {
            count++; 
        }
    }

    if (count != 3) {
        return 0; 
    }

    char *ip_copy = (char *)malloc(strlen(ip));
    strcpy(ip_copy, ip); // Save original ip as strtok destructs it

    char *part = strtok(ip_copy, "."); 
    if (!part) 
        return 0; 
  
    while (part) { 
        if (is_valid_ip_part(part)) { 
            part = strtok(NULL, "."); 
            if (part) {
                dots++; 
            }
        }
        else {
            return 0; 
        }
    }
  
    /* valid IP string must contain 3 dots */
    // this is for the cases such as 1...1 where originally the 
    // no. of dots is three but after iteration of the string we find it is not valid 
    if (dots != 3) {
        return 0; 
    }
    free(ip_copy);
    return 1;
} 

int is_valid_domain(char domain[]) {
    int n = strlen(domain);

    if (n == 0 || n > 255) {
        return 0;
    }

    if (domain[n - 1] == '.') {
        return 0;
    }
    char parts_num = 0;

    char *domain_copy = (char *)malloc(strlen(domain));
    strcpy(domain_copy, domain); // Save original domain as strtok destructs it
    char *part = strtok(domain_copy, ".");

    while (part) {
        n = strlen(part);
        for (int i = 0; i < n; i++) {
            if (((part[i] >= '0' && part[i] <= '9') ||
                 (part[i] >= 'a' && part[i] <= 'z')) == 0) {
                return 0;
            }
        }
        part = strtok(NULL, ".");
        parts_num++;
    }
    free(domain_copy);
    return parts_num > 1;
}