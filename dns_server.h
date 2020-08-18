#include <stdlib.h>


struct dns_header {
    int id;
    char qr;
    char opcode;
    char aa;
    char tc;
    char rd;
    char ra;
    char z;
    char rcode;
    int qdcount;
    int ancount;
    int nscount;
    int arcount;
};

enum record_type {
    A = 1,
    type_unknown
};

enum record_class {
    IN = 1,
    class_unknown
};

struct resource_record {
    char domain[255];
    int ttl;
    unsigned char *data;
    int rdlen;
    enum record_type rtype;
    enum record_class rclass;
    struct resource_record *next;
};

struct dns_packet {
    struct dns_header header;
    struct resource_record *questions;
    struct resource_record *answers;
    struct resource_record *authorities;
    struct resource_record *additional;
};

void read_packet(const char packet[], struct dns_packet *dns_packet);

const char * read_header(const char packet[], struct dns_header *header);

const char * read_domain(const char packet_ptr[], const char *start, char *domain);

const char * read_questions(const char packet_ptr[], const char packet_start[], 
            int qdcount, struct resource_record *questions);

const char * read_records(const char packet_ptr[], const char packet_start[], 
            int rcount, struct resource_record *records);

void read_ipv4(const unsigned char packet_ptr[], unsigned char *address);

int  write_packet(char packet[], const struct dns_packet *dns_packet);

char * write_header(char packet[], const struct dns_packet *dns_packet);

char * write_qname(unsigned char *packet_ptr, const char *domain);

char * write_questions(char packet[], int qdcount, const struct resource_record *questions);

char * write_record(char packet[], int rcount, const struct resource_record *records);

char * write_ipv4(unsigned char *packet_ptr, unsigned char address[]);