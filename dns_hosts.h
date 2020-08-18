#include "hash_table.h"

/* Read hosts information from file in memory */
void read_hosts(HashTable *ht, const char filename[]);

/* Print hosts table from memory*/
void print_hosts(HashTable *ht);

/* Add new host to hosts table */
void add_host(HashTable *ht, char domain[], char data[]);

/* Remove host from hosts table if exists*/
void delete_host(HashTable *ht, char domain[]);

/* Save hosts table from memory into file */
void write_hosts(HashTable *ht, char filename[]);
