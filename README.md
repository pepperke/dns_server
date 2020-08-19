# DNS server

A simple DNS server written in C for a job interview.

To build it, perform

<pre>
git clone https://github.com/pepperke/dns_server.git
cd dns_server
gcc -o dns_server dns_server.c dns_hosts.c hash_table.c -Werror
</pre>

After build you can launch <code>dns_server</code> with

<pre>
./dns_server [filename]
</pre>

with an optional file name which contains hostname information. If not specified, file <code>hosts</code> is read by default. Domains can contain multiple IPs.

During server work, you can modify hosts table which is contained in memory by using:

<pre>
host add *domain* *ip* // To add hostname to table

host delete *domain*   // To delete hostname from table

host print             // To print current table   

host save *filename*   // To save current table to file *filename*
</pre>

A server is bound to listen on <code>10053</code> port so not to interfere with other DNS servers installed on machine.

You can end <code>dns_server</code> work with <code>Ctrc-C</code>.
