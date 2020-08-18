#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "dns_server.h"
#include "dns_hosts.h"
#include "hashtable.c"

int main() {
    hashtable_t *ht = ht_create(1000);

    struct addrinfo *bind_addr, hints;
    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(0, "10053", &hints, &bind_addr)) {
        perror("Failed to get address info");
        exit(1);
    }

    int server_socket = socket(bind_addr->ai_family, bind_addr->ai_socktype, 
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

    printf("Server is started, waiting for connections\n");

    struct dns_packet dns_packet;

    unsigned char query_buff[512];

    // int bytes_written = write_packet(query_buff, &dns_packet);
    // printf("%d\n", bytes_written);

    return 0;
}

void read_ipv4(const unsigned char packet_ptr[], unsigned char *address) {
    sprintf(address, "%u.%u.%u.%u", packet_ptr[0], packet_ptr[1], 
            packet_ptr[2], packet_ptr[3]);
}

const char * read_domain(const char packet_ptr[], const char packet_start[], char domain[]) {
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
        switch (header->rcode) {
            case 0: printf("RCODE: success\n"); break;
            case 1: printf("RCODE: format error\n"); break;
            case 2: printf("RCODE: server failure\n"); break;
            case 3: printf("RCODE: name error\n"); break;
            case 4: printf("RCODE: not implemented\n"); break;
            case 5: printf("RCODE: refused\n"); break;
            default: printf("RCODE: ?\n"); break;
        }
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
        packet_ptr = read_domain(packet_ptr, packet_start, questions->domain);

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
        packet_ptr = read_domain(packet_ptr, packet_start, records->domain);

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

    packet_ptr = read_header(packet_ptr, &(dns_packet->header));

    if (dns_packet->header.qdcount) {
        dns_packet->questions = malloc(sizeof(struct resource_record));
        packet_ptr = read_questions(packet_ptr, packet, dns_packet->header.qdcount,
                    dns_packet->questions);
    }

    if (dns_packet->header.ancount) {
        dns_packet->answers = malloc(sizeof(struct resource_record));
        packet_ptr = read_records(packet_ptr, packet, dns_packet->header.ancount,
                    dns_packet->answers);
    }

    if (dns_packet->header.nscount) {
        dns_packet->authorities = malloc(sizeof(struct resource_record));
        packet_ptr = read_records(packet_ptr, packet, dns_packet->header.nscount,
                    dns_packet->authorities);
    }

    if (dns_packet->header.arcount) {
        dns_packet->additional = malloc(sizeof(struct resource_record));
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

char * write_record(char packet[], int rcount, const struct resource_record *records) {
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
        packet_ptr = write_record(packet_ptr, dns_packet->header.ancount, 
                dns_packet->answers);
    }

    if (dns_packet->header.nscount) {
        packet_ptr = write_record(packet_ptr, dns_packet->header.nscount, 
                dns_packet->authorities);
    }

    if (dns_packet->header.arcount) {
        packet_ptr = write_record(packet_ptr, dns_packet->header.arcount, 
                dns_packet->additional);
    }
    return packet_ptr - packet - 1;
}
