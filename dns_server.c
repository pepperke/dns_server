#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void get_name(const unsigned char message[], const unsigned char *end);
void print_dns_msg(const unsigned char message[], int msg_len);

int main() {
    char query[] = {
        0xAB, 0xBC,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm',
        0,
        0x00, 0x01,
        0x00, 0x01
    };

    print_dns_msg(query, 29);   
    return 0;
}

void get_name(const unsigned char message[], const unsigned char *end) {
    unsigned char len;
    int offset;

    const unsigned char *msg_ptr = message + 12;
    if (msg_ptr + 1 > end) {
        printf("packet is corrupted\n");
        return;
    }

    while (*msg_ptr != 0) {
        if ((*msg_ptr & 0xC0) == 0xC0) {
            if (msg_ptr + 1 > end) {
                printf("packet is corrupted\n");
                return;
            }
            offset = ((*msg_ptr & 0x3F) << 8) | msg_ptr[1];
            msg_ptr = message + offset;
        }
        else {
            len = *msg_ptr++;
            if (msg_ptr + len > end) {
                printf("packet is corrupted\n");
                return;
            }
            printf("%.*s", len, msg_ptr);
            msg_ptr += len;
            if (*msg_ptr != 0) {
                printf(".");
            }
        }
    }
}

void print_dns_msg(const unsigned char message[], int msg_len) {
    if (msg_len < 12) {
        printf("Packet is too short\n");
        exit(1);
    }
    const unsigned char *msg_ptr = message;
    printf("ID: %0x %0x\n", msg_ptr[0], msg_ptr[1]);

    char qr = (msg_ptr[2] & 0x80) >> 7;
    printf("QR: %d - %s\n", qr, qr ? "response" : "query");

    char opcode = (msg_ptr[2] & 0x78) >> 3;
    printf("Opcode: %d\n", opcode);

    char aa = (msg_ptr[2] & 0x04) >> 2;
    printf("AA: %d\n", aa);

    char tc = (msg_ptr[2] & 0x02) >> 1;
    printf("AA: %d\n", tc);

    char rd = (msg_ptr[2] & 0x01);
    printf("RD: %d\n", rd);

    if (qr) {
        char rcode = (msg_ptr[3] & 0x0F);
        switch (rcode) {
            case 0: printf("RCODE: success\n"); break;
            case 1: printf("RCODE: format error\n"); break;
            case 2: printf("RCODE: server failure\n"); break;
            case 3: printf("RCODE: name error\n"); break;
            case 4: printf("RCODE: not implemented\n"); break;
            case 5: printf("RCODE: refused\n"); break;
            default: printf("RCODE: ?\n"); break;
        }
        if (rcode != 0) return;
    }

    int qdcount = (msg_ptr[4] << 8) | msg_ptr[5];
    int ancount = (msg_ptr[6] << 8) | msg_ptr[7];
    int nscount = (msg_ptr[8] << 8) | msg_ptr[9];
    int arcount = (msg_ptr[10] << 8) | msg_ptr[11];

    printf("QDCOUNT: %d\n", qdcount);
    printf("ANCOUNT: %d\n", ancount);
    printf("NSCOUNT: %d\n", nscount);
    printf("ARCOUNT: %d\n", arcount);

    if (qdcount) {
        for (int i = 0; i < qdcount; i++) {
            

            printf("Query #%2d\n", i+1);
            get_name(message, message + msg_len);

        }
    }
}