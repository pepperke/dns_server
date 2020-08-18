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

        if (!data) {
            fprintf(stderr, "Failed to process hosts on line %d, exiting\n", line_num);
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