/* Structure to hold DNS Header data*/
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

/* Types of Resource Record*/
enum record_type {
    A = 1,
    type_unknown
};

/* Classes of Resource Record*/
enum record_class {
    IN = 1,
    class_unknown
};

/* Rcode for DNS header */
enum rcode {
    NOERROR,
    FORMAT_ERROR,
    SERVER_FAILURE,
    NAME_ERROR,
    NOT_IMPLEMENTED,
    NOT_REFUSED
};

/* Structure to hold DNS Resource Record data*/
struct resource_record {
    char domain[255];
    int ttl;
    unsigned char *data;
    int rdlen;
    enum record_type rtype;
    enum record_class rclass;
    struct resource_record *next;
};

/* Structure to hold DNS packet data*/
struct dns_packet {
    struct dns_header header;
    struct resource_record *questions;
    struct resource_record *answers;
    struct resource_record *authorities;
    struct resource_record *additional;
};

/* Translate bytes array into dns_packet structure */
void read_packet(const char packet[], struct dns_packet *dns_packet);

/* Fill dns_header from bytes array */
const char * read_header(const char packet[], struct dns_header *header);

/* Read domain from labels and write it into *domain* variable */
const char * read_qname(const char packet_ptr[], const char *start, char *domain);

/* Read questions from bytes array */
const char * read_questions(const char packet_ptr[], const char packet_start[], 
            int qdcount, struct resource_record *questions);

/* Read resource records from bytes array */
const char * read_records(const char packet_ptr[], const char packet_start[], 
            int rcount, struct resource_record *records);

/* Read IPv4 address from binary format into *address* variable */
void read_ipv4(const unsigned char packet_ptr[], unsigned char *address);

/* Translate dns_packet structure into bytes array */
int  write_packet(char packet[], struct dns_packet *dns_packet);

/* Write header into bytes array */
char * write_header(char packet[], const struct dns_packet *dns_packet);

/* Split domain on labels and write them into Query section of bytes array */
char * write_qname(unsigned char *packet_ptr, const char *domain, int *space_left);

/* Write questions into bytes array */
char * write_questions(char packet[], int qdcount, const struct resource_record *questions,
            int *space_left);

/* Write resource record info into bytes array */
char * write_records(char packet[], int rcount, const struct resource_record *records,
            int *space_left);

/* Write IPv4 address in binary format into bytes array */
char * write_ipv4(unsigned char *packet_ptr, unsigned char address[]);

/* Free allocated memory for dns_packet */
void free_dns_packet(struct dns_packet *dns_packet);

/* Read query and send answer */
void process_query();

/* Process command that user entered from terminal */
void process_user_command(char command[]);
