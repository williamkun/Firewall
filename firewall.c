#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/time.h>

#include <linux/netlink.h>
#include <linux/sched.h>
#include <net/sock.h>

#define MAX_BUFFER_SIZE 512
#define PROCF_MAX_SIZE 1024
#define PROCF_NAME "swaruardfirewall"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Swaruardfirewall");
MODULE_AUTHOR("Swaruard");

//the virtual proc_file
static struct proc_dir_entry *mf_proc_file;
//the position of the buffer to write
unsigned long procf_buffer_pos;
//the procf_buffer
char *procf_buffer;
//the hook of IN packet
static struct nf_hook_ops nfho;
//the hook of OUT packet
static struct nf_hook_ops nfho_out;
//the policy list to filter the packet
static struct mf_rule policy_list;

//The var of the netlink
#define NETLINK_REALNET 26
#define MAX_MSGSIZE 1024
int stringlength(const char *s);
void sendnlmsg(const char *message);
struct sock *nl_sk = NULL;
int pid;
int err;
int flag = 0;



void sendnlmsg(const char *message)
{
    struct sk_buff *temp_skb;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen = 0;
    if(!message || !nl_sk)
        return ;
    temp_skb = alloc_skb(len, GFP_KERNEL);
    if(!temp_skb)
        printk(KERN_ERR "Allocate error.\n");
    slen = stringlength(message);
    nlh = nlmsg_put(temp_skb, 0, 0, 0, MAX_MSGSIZE, 0);
    NETLINK_CB(temp_skb).pid = 0;
    NETLINK_CB(temp_skb).dst_group = 0;
    memcpy(NLMSG_DATA(nlh), message, slen + 1);
    netlink_unicast(nl_sk, temp_skb, pid, MSG_DONTWAIT);
}

int stringlength(const char *s)
{
    int slen = 0;
    for(; *s; s++)
        slen++;
    return slen;
}


void nl_data_ready(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char str[100];
    //struct completion cmpl;
    skb = skb_get(__skb);
    if(skb->len >= NLMSG_SPACE(0))
    {
        nlh = nlmsg_hdr(skb);
        memcpy(str, NLMSG_DATA(nlh), sizeof(str));
        pid = nlh->nlmsg_pid;
        //init_completion(&cmpl);
        //wait_for_completion_timeout(&cmpl, 3 * HZ);
        flag = 1;
        kfree_skb(skb);
    }
}

void send_packet_to_user(const char *message)
{
    sendnlmsg(message);
}


/**
 * the description of the firewall rule
 * ATTENTION: the members in the mf_rule_desp all have relation with the char type
 */
struct mf_rule_desp
{
    unsigned char in_out;
    char *src_ip;
    char *src_netmask;
    char *src_port;
    char *dest_ip;
    char *dest_netmask;
    char *dest_port;
    unsigned char proto;
    unsigned char action;
};


/**
 * the firewall rule's structure
 */
struct mf_rule
{
    unsigned char in_out;
    unsigned int src_ip;
    unsigned int src_netmask;
    unsigned int src_port;
    unsigned int dest_ip;
    unsigned int dest_netmask;
    unsigned int dest_port;
    unsigned char proto;//0 stands for ALL; 1 stands for TCP; 2 stands for UDP
    unsigned char action;//0 stands for BLOCK; 1 stands for UNBLOCK;
    struct list_head list;//kernel list
};


/**
 * convert the str port to unsigned int port
 * port_str: the Big-Endian byte array to conver
 * ATTENTION: the port_str is a byte array which is different between the host and network
 * The network's byte order is Big-Endian while most of the PCs' byte order is Little-Endian
 */
unsigned int port_str_to_int(char *port_str)
{
    unsigned int port = 0;
    int i = 0;
    if(port_str == NULL)
        return 0;
    while(port_str[i] != '\0')
    {
        port = port * 10 + (port_str[i] - '0');
        ++i;
    }
    return port;
}

size_t strlen(const char *string)
{
    size_t i = 0;
    while(string[i++]);
    i--;
    return i;
}


/**
 * convert the unsigned int port to str port
 * port: the integer type port to convert to char *
 * port_str: the char * type to store the result of the conversion
 */
void port_int_to_str(unsigned int port, char *port_str)
{
    sprintf(port_str,"%u",port);
}


/**
 * convert the str ip to unsigned int ip address
 * ip_str: the Big-Endian byte array to convert
 * return_value:
 * the unsigned int type of the ip address
 */
unsigned int ip_str_to_hl(char *ip_str)
{
    unsigned char ip_array[4];
    int i = 0;
    unsigned int ip = 0;
    if(ip_str == NULL)
        return 0;
    memset(ip_array, 0, 4);
    while(ip_str[i]!='.')
        ip_array[0] = ip_array[0] * 10 + (ip_str[i++] - '0');
    ++i;
    while(ip_str[i]!='.')
        ip_array[1] = ip_array[1] * 10 + (ip_str[i++] - '0');
    ++i;
    while(ip_str[i]!='.')
        ip_array[2] = ip_array[2] * 10 + (ip_str[i++] - '0');
    ++i;
    while(ip_str[i]!= '\0')
        ip_array[3] = ip_array[3] * 10 + (ip_str[i++] - '0');
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    return ip;
}


/**
 * convert the unsigned int ip to str ip address
 * ip: the integer type of the ip address to convert
 * ip_str: the char * type to store the result
 */
void ip_hl_to_str(unsigned int ip, char *ip_str)
{
    unsigned char ip_array[4];
    memset(ip_array, 0, 4);
    ip_array[0] = (ip_array[0] | (ip >> 24));
    ip_array[1] = (ip_array[1] | (ip >> 16));
    ip_array[2] = (ip_array[2] | (ip >> 8));
    ip_array[3] = (ip_array[3] | ip);
    sprintf(ip_str,"%u.%u.%u.%u",ip_array[0],ip_array[1],ip_array[2],ip_array[3]);
}


/**
 * compare the ip address and the ip address in ip_rule whether in the same subnetwork
 * ip: the specific ip address to compare
 * ip_rule: the ip in the filter policy to compare
 * mask: the submask decide whether the ip and ip_rule are in the same subnetwork
 */
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask)
{
    unsigned int tmp = ntohl(ip);
    int cmp_len = 32;
    int i = 0, j = 0;
    //printk(KERN_INFO "compare ip %u <=> %u\n",tmp,ip_rule);
    if(mask != 0)
    {
        cmp_len = 0;
        for(i = 0; i < 32; i++)
        {
            if(mask & (1 << (32-1-i)))
                cmp_len++;
            else
                break;
        }
    }
    for(i = 31, j = 0; i < cmp_len; --i, ++j)
    {
        if((tmp & (1 << i)) != (ip_rule & (1 << i)))
        {
            //printk(KERN_INFO "ip compare: %d bit doesn't match\n",(32 - i));
            return false;
        }
    }
    return true;
}



/**
 * add a rule to the policy which use to filter the packets
 * a_rule_desp: the description of the rule to add to the filter policy
 */
void add_a_rule(struct mf_rule_desp *a_rule_desp)
{
    struct mf_rule *a_rule;
    a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
    if(a_rule == NULL)
    {
        printk(KERN_INFO "Error: cannot allocate memory for a new rule.\n");
        return;
    }
    //1.in or out
    a_rule->in_out = a_rule_desp->in_out;
    //2.src_ip
    if(strcmp(a_rule_desp->src_ip,"-") != 0)
        a_rule->src_ip = ip_str_to_hl(a_rule_desp->src_ip);
    else
        a_rule->src_ip = (unsigned int)NULL;
    //3.src_netmask
    if(strcmp(a_rule_desp->src_netmask,"-") != 0)
        a_rule->src_netmask = ip_str_to_hl(a_rule_desp->src_netmask);
    else
        a_rule->src_netmask = (unsigned int)NULL;
    //4.src_port
    if(strcmp(a_rule_desp->src_port,"-") != 0)
        a_rule->src_port = port_str_to_int(a_rule_desp->src_port);
    else
        a_rule->src_port = (unsigned int)NULL;
    //5.dest_ip
    if(strcmp(a_rule_desp->dest_ip,"-") != 0)
        a_rule->dest_ip = ip_str_to_hl(a_rule_desp->dest_ip);
    else
        a_rule->dest_ip = (unsigned int)NULL;
    //6.dest_netmask
    if(strcmp(a_rule_desp->dest_netmask,"-") != 0)
        a_rule->dest_netmask = ip_str_to_hl(a_rule_desp->dest_netmask);
    else
        a_rule->dest_netmask = (unsigned int)NULL;
    //7.dest_port
    if(strcmp(a_rule_desp->dest_port,"-") != 0)
        a_rule->dest_port = port_str_to_int(a_rule_desp->dest_port);
    else
        a_rule->dest_port = (unsigned int)NULL;
    //8.proto
    a_rule->proto = a_rule_desp->proto;
    //9.action
    a_rule->action = a_rule_desp->action;
    printk(KERN_INFO "Add_a_rule: in_out=%u, src_ip=%u, src_netmask=%u, src_port=%u, "
            "dest_ip=%u, dest_netmask=%u, dest_port=%u, proto=%u, action=%u\n",\
            a_rule->in_out,a_rule->src_ip,a_rule->src_netmask,a_rule->src_port,\
            a_rule->dest_ip,a_rule->dest_netmask,a_rule->dest_port,a_rule->proto,a_rule->action);
    INIT_LIST_HEAD(&(a_rule->list));
    list_add_tail(&(a_rule->list), &(policy_list.list));
}



/**
 * allocate the memory of the description of the firewall rule and set some default value
 * a_rule_desp: the description of the rule to initialize
 */
void init_mf_desp(struct mf_rule_desp *a_rule_desp)
{
    a_rule_desp->in_out = 0;
    a_rule_desp->src_ip = (char *)kmalloc(16,GFP_KERNEL);
    a_rule_desp->src_netmask = (char *)kmalloc(16,GFP_KERNEL);
    a_rule_desp->src_port = (char *)kmalloc(16,GFP_KERNEL);
    a_rule_desp->dest_ip = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->dest_netmask = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->dest_port = (char *)kmalloc(16, GFP_KERNEL);
    a_rule_desp->proto = 0;
    a_rule_desp->action = 0;
}



/**
 * delete a rule which was specified by num in the policy
 * num: specify the location of the rule to delete
 * ATTENTION: we have to use the list_for_each_safe but not the list_for_each
 */
void delete_a_rule(int num)
{
    int i = 0;
    struct list_head *p,*q;
    struct mf_rule *a_rule;
    printk(KERN_INFO "Delete a rule: %d\n",num);
    list_for_each_safe(p,q,&policy_list.list)
    {
        ++i;
        if(i==num)
        {
            a_rule = list_entry(p,struct mf_rule,list);
            list_del(p);
            kfree(a_rule);
            return;
        }
    }
}



/**
 * read the procf_buffer to the user buffer
 * buffer: the user buffer to store the read result
 * buffer_location: the begin of the user buffer to write 
 * offset: the same as the read function indicates the offset of the file
 * buffer_length: the same as the read function indicates the count to read
 * eof: indicates the end of the file which is a output value
 * data: non-use
 * return_value:
 * the num of the procf_buffer copy to the user buffer
 */
int procf_read(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
    int ret;
    struct mf_rule *a_rule;
    char token[20];
    //printk(KERN_INFO "procf_read(/proc/%s)called\n",PROCF_NAME);
    if(offset > 0)
    {
        printk(KERN_INFO "eof is 1, nothing to read\n");
        *eof = 1;
        return 0;
    }
    else
    {
        procf_buffer_pos = 0;
        ret = 0;
        list_for_each_entry(a_rule,&policy_list.list,list)
        {
            //example of the procf_buffer:
            //in 192.168.12.2 255.255.255.0 - 192.168.12.6 255.255.255.0 - ALL BLOCK\n
            //out 192.168.12.2 255.255.255.0 - 192.168.12.10 255.255.255.0 - TCP BLOCK\n
            //1.in or out
            if(a_rule->in_out == 1)
                strcpy(token,"in");
            else if(a_rule->in_out == 2)
                strcpy(token,"out");
            //printk(KERN_INFO "token:%s\n", token);
            memcpy(procf_buffer+procf_buffer_pos,token,strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos," ",1);
            procf_buffer_pos++;
            //2.src_ip
            if(a_rule->src_ip == (unsigned int)NULL)
                strcpy(token,"-");
            else
                ip_hl_to_str(a_rule->src_ip,token);
            //printk(KERN_INFO ""
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ",1);
            procf_buffer_pos++;
            //3.src_netmask
            if(a_rule->src_netmask == (unsigned int)NULL)
                strcpy(token,"-");
            else
                ip_hl_to_str(a_rule->src_netmask,token);
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos," ",1);
            procf_buffer_pos++;
            //4.src_port
            if(a_rule->src_port == 0)
                strcpy(token,"-");
            else
                port_int_to_str(a_rule->src_port,token);
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos," ",1);
            procf_buffer_pos++;
            //5.dest_ip
            if(a_rule->dest_ip == (unsigned int)NULL)
                strcpy(token,"-");
            else
                ip_hl_to_str(a_rule->dest_ip,token);
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos," ",1);
            procf_buffer_pos++;
            //6.dest_netmask
            if(a_rule->dest_netmask == (unsigned int)NULL)
                strcpy(token,"-");
            else
                ip_hl_to_str(a_rule->dest_netmask,token);
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos," ",1);
            procf_buffer_pos++;
            //7.dest_port
            if(a_rule->dest_port == 0)
                strcpy(token,"-");
            else
                port_int_to_str(a_rule->dest_port,token);
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos," ",1);
            procf_buffer_pos++;
            //8.proto
            if(a_rule->proto == 0)
                strcpy(token,"ALL");
            else if(a_rule->proto == 1)
                strcpy(token,"TCP");
            else if(a_rule->proto == 2)
                strcpy(token,"UDP");
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, " ", 1);
            procf_buffer_pos++;
            //9.action
            if(a_rule->action == 0)
                strcpy(token,"BLOCK");
            else if(a_rule->action == 1)
                strcpy(token,"UNBLOCK");
            //printk(KERN_INFO "token:%s\n",token);
            memcpy(procf_buffer + procf_buffer_pos, token, strlen(token));
            procf_buffer_pos += strlen(token);
            memcpy(procf_buffer + procf_buffer_pos, "\n", 1);
            procf_buffer_pos++;
        }
        //procf_buffer_pos indicates the end of the procf_buffer
        //printk(KERN_INFO "procf_buffer_pos:%ld\n",procf_buffer_pos);
        //copy the procf_buffer to the user buffer
        //ATTENTION: the procf_buffer_pos indicates the num of the procf_buffer to copy
        memcpy(buffer,procf_buffer,procf_buffer_pos);
        ret = procf_buffer_pos;
    }
    return ret;
}



/**
 * write the user buffer to the procf_buffer
 * add the rule in the procf to the policy_list
 * file:
 * buffer: the buffer to write to the proc_file
 * count: the write buffer count
 * data:non-use
 * return_value:
 * the num of the write buffer
 */
int procf_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
    int i,j;
    struct mf_rule_desp *rule_desp;
    //printk(KERN_INFO "procf_write is called.\n");
    procf_buffer_pos = 0;
    //printk(KERN_INFO "pos %ld; count:%ld\n",procf_buffer_pos,count);
    if(procf_buffer_pos + count > PROCF_MAX_SIZE)
    {
        //the max procf_buffer size was left
        count = PROCF_MAX_SIZE - procf_buffer_pos;
    }
    //copy the user buffer to the kernel buffer
    //ATTENTION: the procf_buffer_pos indicates the current end of the procf_buffer
    //what's more it's the begin after copy the user buffer to the procf_buffer
    if(copy_from_user(procf_buffer + procf_buffer_pos,buffer,count))
        return -EFAULT;
    printk(KERN_INFO "procf_buffer: %s\n",procf_buffer);
    //print command
    if(procf_buffer[procf_buffer_pos] == 'p')
        return 0;
    //delete command
    //example:
    //d12 
    else if(procf_buffer[procf_buffer_pos] == 'd')
    {
        //to get the num of the rule to delete
        i = procf_buffer_pos + 1;
        j = 0;
        while((procf_buffer[i]!=' ') && (procf_buffer[i] != '\n'))
        {
            //to find which rule to delete in the procf_buffer
            //printk(KERN_INFO "delete %d\n",procf_buffer[i] - '0');
            j = j * 10 + (procf_buffer[i] - '0');
            ++i;
        }
        delete_a_rule(j);
        return count;
    }

    //add a new rule to the policy_list
    //the default action is to add a new rule
    rule_desp = kmalloc(sizeof(*rule_desp),GFP_KERNEL);
    if(rule_desp == NULL)
    {
        printk(KERN_INFO "Error:cannot allocate memory for rule_desp\n");
        return -ENOMEM;
    }
    init_mf_desp(rule_desp);
    i = procf_buffer_pos;
    //1.in or out
    j = 0;
    if(procf_buffer[i] != ' ')
        rule_desp->in_out = (unsigned char)(procf_buffer[i++] - '0');
    ++i;
    //printk(KERN_INFO "in or out : %u\n",rule_desp->in_out);
    //2.src_ip
    j = 0;
    while(procf_buffer[i] != ' ')
        rule_desp->src_ip[j++] = procf_buffer[i++];
    ++i;
    rule_desp->src_ip[j] = '\0';
    //printk(KERN_INFO "src ip:%s\n",rule_desp->src_ip);
    //3.src_netmask
    j = 0;
    while(procf_buffer[i]!=' ')
    {
        rule_desp->src_netmask[j++] = procf_buffer[i++];
    }
    ++i;
    rule_desp->src_netmask[j] = '\0';
    //printk(KERN_INFO "src netmask: %s\n",rule_desp->src_netmask);
    //4.src_port
    j = 0;
    while(procf_buffer[i]!=' ')
        rule_desp->src_port[j++] = procf_buffer[i++];
    ++i;
    rule_desp->src_port[j] = '\0';
    //printk(KERN_INFO "src_port:%s\n",rule_desp->src_port);
    //5.dest_ip
    j = 0;
    while(procf_buffer[i] !=' ')
        rule_desp->dest_ip[j++] = procf_buffer[i++];
    ++i;
    rule_desp->dest_ip[j] = '\0';
    //printk(KERN_INFO "dest ip:%s\n",rule_desp->dest_ip);
    //6.dest_netmask
    j = 0;
    while(procf_buffer[i] != ' ')
        rule_desp->dest_netmask[j++] = procf_buffer[i++];
    ++i;
    rule_desp->dest_netmask[j] = '\0';
    //printk(KERN_INFO "dest netmark%s\n",rule_desp->dest_netmask);
    //7.dest_port
    j = 0;
    while(procf_buffer[i] != ' ')
        rule_desp->dest_port[j++] = procf_buffer[i++];
    ++i;
    rule_desp->dest_port[j] = '\0';
    //printk(KERN_INFO "dest port:%s\n",rule_desp->dest_port);
    //8.proto
    j = 0;
    if(procf_buffer[i] != ' ')
    {
        if(procf_buffer[i] != '-')
            rule_desp->proto = (unsigned char)(procf_buffer[i++] - '0');
        else
            ++i;
    }
    ++i;
    //printk(KERN_INFO "proto:%d\n",rule_desp->proto);
    //9.action
    j = 0;
    if(procf_buffer[i] != ' ')
    {
        if(procf_buffer[i] != '-')
            rule_desp->action = (unsigned char)(procf_buffer[i++] - '0');
        else
            ++i;
    }
    ++i;
    //printk(KERN_INFO "action:%d\n",rule_desp->action);
    add_a_rule(rule_desp);
    kfree(rule_desp);
    //printk(KERN_INFO "------------------\n");
    return count;
}


/**
 * handle the OUT packet
 * hooknum: the five types of the hook
 * skb: the socket buffer to store the packet
 * in: the IN device structure
 * out: the OUT device structure
 * okfn:
 * return_value:
 */
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
    char temp[64];
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct list_head *p;
    struct mf_rule *a_rule;
    char src_ip_str[16],dest_ip_str[16];
    char send_info[MAX_BUFFER_SIZE];
    size_t send_info_length = 0;
    struct timeval tv;
    int i = 0;
    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int)ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;
    //UDP protocol
    if(ip_header->protocol == 17)
    {
        udp_header = (struct udphdr*)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(udp_header->source);
        dest_port = (unsigned int)ntohs(udp_header->dest);
    }
    //TCP protocol
    else if(ip_header->protocol == 6)
    {
        tcp_header = (struct tcphdr*)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    ip_hl_to_str(ntohl(src_ip),src_ip_str);
    ip_hl_to_str(ntohl(dest_ip),dest_ip_str);
    do_gettimeofday(&tv);
    sprintf(send_info,"out#%s#%u#%s#%u#%u#%ld#%ld#",src_ip_str,src_port,\
            dest_ip_str,dest_port,ip_header->protocol,(long)tv.tv_sec,(long)tv.tv_usec);
    send_info_length = strlen(send_info);
    //match the rules
    list_for_each(p,&policy_list.list)
    {
        i++;
        a_rule = list_entry(p,struct mf_rule, list);
        if(a_rule->in_out != 2)
        {
            printk(KERN_INFO "hook_out: out\n");
            continue;
        }
        else
        {
            //ATTENTION: the compare with 0 means that if the filter policy doesn't specify the information
            //the compare will continue to compare the next item
            if((a_rule->proto==1) &&(ip_header->protocol != 6))
            {
                printk(KERN_INFO "hook_out: TCP\n");
                continue;
            }
            else if((a_rule->proto == 2)&&(ip_header->protocol != 17))
            {
                printk(KERN_INFO "hook_out: UDP\n");
                continue;
            }
            if(a_rule->src_ip == 0)
            {
                printk(KERN_INFO "hook_out: src_ip is NULL\n");
            }
            else
            {
                if(!check_ip(src_ip,a_rule->src_ip,a_rule->src_netmask))
                {
                    printk(KERN_INFO "hook_out: src is not match.\n");
                    continue;
                }
            }            
            //Change the way to comapre the ip
            ip_hl_to_str(a_rule->dest_ip, temp);
            if(strcmp(dest_ip_str, temp) == 0)
                printk(KERN_INFO "dest is the same.\n");
            else
                printk(KERN_INFO "dest is not match.\n");
            /*
            if(a_rule->dest_ip == 0)
            {
                printk(KERN_INFO "hook_out: dest_ip is NULL\n");
            }
            else
            {
                if(!check_ip(dest_ip, a_rule->dest_ip,a_rule->dest_netmask))
                {
                    printk(KERN_INFO "hook_out: dest_ip is not match.\n");
                    continue;
                }
            }
            */
            if(a_rule->src_port == 0)
            {
                printk(KERN_INFO "hook_out: src_port is NULL\n");
            }
            else if(src_port != a_rule->src_port)
            {
                printk(KERN_INFO "hook_out: src_port is not match.\n");
                continue;
            }
            if(a_rule->dest_port == 0)
            {
                printk(KERN_INFO "hook_out: dest_ip is NULL.\n");
            }
            else if(dest_port != a_rule->dest_port)
            {
                printk(KERN_INFO "hook_out: dest_ip is not match.\n");
                continue;
            }
            //action:
            //0: BLOCK the packet
            //1: UNBLOCK the packet
            if(a_rule->action == 0)
            {
                printk(KERN_INFO "a match is found:%d,drop the packet\n",i);
                sprintf(&send_info[send_info_length],"BLOCK#");
                sendnlmsg(send_info);
                //printk(KERN_INFO "--------------------\n");
                return NF_DROP;
            }
            else
            {
                printk(KERN_INFO "a match is found:%d, accept the packet\n",i);
                sprintf(&send_info[send_info_length],"UNBLOCK#");
                sendnlmsg(send_info);
                //printk(KERN_INFO "----------------------\n");
                return NF_ACCEPT;
            }
        }
    }
    sprintf(&send_info[send_info_length],"UNBLOCK#");
    sendnlmsg(send_info);
    //if there is no match return the defaul policy: UNBLOCK
    //printk(KERN_INFO "--------------------\n");
    return NF_ACCEPT;
}


/**
 * handle the IN packet
 * hooknum: one of the five types of the hook
 * skb: the socket buffer
 * in: the IN device struct
 * out: the OUT device struct
 * okfn:
 * return_value:
 */
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*))
{
    struct iphdr *ip_header = (struct iphdr*)skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct list_head *p;
    struct mf_rule *a_rule;
    char src_ip_str[16],dest_ip_str[16];
    int i = 0;
    struct timeval tv;
    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int)ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;
    size_t send_info_length = 0;
    char send_info[MAX_BUFFER_SIZE];
    if(ip_header->protocol == 17)
    {
        udp_header = (struct udphdr*)(skb_transport_header(skb) + 20);
        src_port = (unsigned int)ntohs(udp_header->source);
        dest_port = (unsigned int)ntohs(udp_header->dest);
    }
    else if(ip_header->protocol == 6)
    {
        tcp_header = (struct tcphdr *)(skb_transport_header(skb) + 20);
        src_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    ip_hl_to_str(ntohl(src_ip),src_ip_str);
    ip_hl_to_str(ntohl(dest_ip),dest_ip_str);
    do_gettimeofday(&tv);
    sprintf(send_info,"in#%s#%u#%s#%u#%u#%ld#%ld#",src_ip_str,src_port,\
            dest_ip_str,dest_port,ip_header->protocol,(long)tv.tv_sec,(long)tv.tv_usec);
    send_info_length = strlen(send_info);
    list_for_each(p,&policy_list.list)
    {
        i++;
        a_rule = list_entry(p,struct mf_rule, list);
        if(a_rule->in_out != 1)
        {
            //printk(KERN_INFO "rule %d(a_rule->in_out:%u) not match: in packet, rule doesn't specify as in\n",i,a_rule->in_out);
            continue;
        }
        else
        {
            if((a_rule->proto == 1) && (ip_header->protocol != 6))
            {
                //printk(KERN_INFO "rule %d notmatch:rule-TCP,packet->not TCP\n",i);
                continue;
            }
            else if((a_rule->proto == 2) && (ip_header->protocol != 17))
            {
                //printk(KERN_INFO "rule %d not match:rule-UDP, packet->not UDP\n",i);
                continue;
            }
            if(a_rule->src_ip == 0)
            {
            }
            else
            {
                if(!check_ip(src_ip,a_rule->src_ip,a_rule->src_netmask))
                {
                    //printk(KERN_INFO "rule %d not match:src ip mismatch\n",i);
                    continue;
                }
            }
            if(a_rule->dest_ip == 0)
            {
            }
            else
            {
                if(!check_ip(dest_ip,a_rule->dest_ip,a_rule->dest_netmask))
                {
                    //printk(KERN_INFO "rule %d not match:dest ip mismatch\n",i);
                    continue;
                }
            }
            if(a_rule->src_port == 0)
            {
            }
            else if(src_port != a_rule->src_port)
            {
                //printk(KERN_INFO "rule %d not match: src port mismatch\n",i);
                continue;
            }
            if(a_rule->dest_port == 0)
            {
            }
            else if(dest_port != a_rule->dest_port)
            {
                //printk(KERN_INFO "rule %d not match: dest port mismatch\n",i);
                continue;
            }
            if(a_rule->action == 0)
            {
                printk(KERN_INFO "a match is found:%d, drop the packet\n",i);
                sprintf(&send_info[send_info_length],"BLOCK#");
                sendnlmsg(send_info);
                //printk(KERN_INFO "-------------------\n");
                return NF_DROP;
            }
            else
            {
                printk(KERN_INFO "a match is found :%d, accept the packet\n",i);
                sprintf(&send_info[send_info_length],"UNBLOCK#");
                sendnlmsg(send_info);
                //printk(KERN_INFO "-------------------\n");
                return NF_ACCEPT;
            }
        }
    }
    sprintf(&send_info[send_info_length],"UNBLOCK#");
    sendnlmsg(send_info);
    //printk(KERN_INFO "no matching is found, accept the packet\n");
    //printk(KERN_INFO "-----------------------\n");
    return NF_ACCEPT;
}


/**
 * install the hook function to handle the packet
 * return_value:
 * 0: succeed; others: fail 
 */
int init_module()
{
    //Netlink:
    nl_sk = netlink_kernel_create(&init_net, NETLINK_REALNET,1,nl_data_ready, NULL, THIS_MODULE);
    if(!nl_sk)
    {
        //printk(KERN_ERR "Netlink create error.\n");
        return 1;
    }
    //printk(KERN_INFO "netlink_created.\n");


    //origin
    printk(KERN_INFO "Initialize the kernel module\n");
    procf_buffer = (char *)vmalloc(PROCF_MAX_SIZE);
    INIT_LIST_HEAD(&(policy_list.list));
    mf_proc_file = create_proc_entry(PROCF_NAME, 0644, NULL);
    if(mf_proc_file == NULL)
    {
        printk(KERN_INFO "Error:coundl not initialize /proc/%s\n",PROCF_NAME);
        return -ENOMEM;
    }
    mf_proc_file->read_proc = procf_read;
    mf_proc_file->write_proc = procf_write;
    //printk(KERN_INFO "/proc/%s is created\n",PROCF_NAME);
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);
    return 0;
}


/**
 * unistall the hook function to unblock the packet
 */
void cleanup_module()
{
    struct list_head *p,*q;
    struct mf_rule *a_rule;
    //Netlink:
    if(nl_sk != NULL)
    {
        sock_release(nl_sk->sk_socket);
    }


    //origin
    nf_unregister_hook(&nfho);
    nf_unregister_hook(&nfho_out);
    //printk(KERN_INFO "free policy_list.list\n");
    list_for_each_safe(p,q,&policy_list.list)
    {
        //printk(KERN_INFO "free one\n");
        a_rule = list_entry(p,struct mf_rule, list);
        list_del(p);
        kfree(a_rule);
    }
    remove_proc_entry(PROCF_NAME,NULL);
    printk(KERN_INFO "Kernel module unloaded.\n");
}
