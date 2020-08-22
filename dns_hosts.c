#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns_hosts.h"

void read_hosts(HashTable *ht, const char filename[]) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("Error opening file");
        exit(1);
    }

    char line_buffer[300];
    int line_num = 0;
    char *domain, *data;
    
    while (fgets(line_buffer, sizeof(line_buffer), fp)) {
        line_num++;
        domain = strtok(line_buffer, " \t");
        data = strtok(NULL, " \t\n");

        if (!is_valid_domain(domain)) {
            printf("Wrong domain format on line %d, exiting\n", line_num);
            exit(1);
        }
        if (!is_valid_ip(data)) {
            printf("Wrong ip format on line %d, exiting\n", line_num);
            exit(1);
        }
        ht_insert(ht, domain, data);
    }
    fclose(fp);
}

void print_hosts(HashTable *ht) {
    print_hashtable(ht);
}

void add_host(HashTable *ht, char domain[], char data[]) {
    ht_insert(ht, domain, data);
}

void delete_host(HashTable *ht, char domain[]) {
    ht_delete(ht, domain);
}

void write_hosts(HashTable *ht, char filename[]) {
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }
    char line_buffer[300];

    for (int i=0; i < ht->size; i++) {
        if (ht->items[i]) {
            sprintf(line_buffer, "%s\t\t%s\n", ht->items[i]->key, ht->items[i]->value);
            fputs(line_buffer, fp);
        }
    }
    fclose(fp);
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
