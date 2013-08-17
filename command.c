#include "command.h"
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include <linux/socket.h>
#include <errno.h>

//Netlink
#define NETLINK_REALNET 26
#define MAX_PAYLOAD 1024

/**
 * the mf_rule mainly store the src and dest information
 */
static struct mf_rule_struct mf_rule;


/**
 * mf_delete is use to store the command to delete a rule in the filter policy
 */
static struct mf_delete_struct mf_delete;

/**
 * write the string to the proc file
 * str: the string to write to the proc file
 */
void send_to_proc(const char *str)
{
    FILE *pf;
    pf = fopen("/proc/swaruardfirewall","w");
    if(pf == NULL)
    {
        fputs("Cannot open the /proc/swaruardfirewall for writing.\n",stderr);
        exit(1);
    }
    else
    {
        fprintf(pf,"%s",str);
    }
    fclose(pf);
    return ;
}


/**
 * return the integer type of the char * type of the proto
 * proto: the char * type of the protocol
 * return_value:
 * 0: ALL; 1: TCP; 2: UDP
 */
int get_proto(const char *proto)
{
    if(strcmp(proto,"ALL") == 0)
    {
        return 0;
    }
    else if(strcmp(proto, "TCP") == 0)
    {
        return 1;
    }
    else if(strcmp(proto, "UDP") == 0)
    {
        return 2;
    }
    else return -1;
}


/**
 * return the integer type of the char * type of the action
 * action: the char * type of the filter policy action
 * return_value:
 * 0: BLOCK; 1: UNBLOCK
 */
int get_action(const char *action)
{
    if(strcmp(action,"BLOCK") == 0)
    {
        return 0;
    }
    else if(strcmp(action, "UNBLOCK") == 0)
    {
        return 1;
    }
    else return -1;
}



void write_record(const char *record_file_path, const char *packet_info)
{
    FILE *fp = fopen(record_file_path, "a+");
    if(!fp)
    {
        fputs("Fopen error.\n",stderr);
        exit(1);
    }
    fwrite(packet_info, strlen(packet_info), 1, fp);
    fwrite("\n", 1, 1, fp);
    fclose(fp);
    return ;
}


/**
 * to form a filter rule to write to the proc file
 * use the static var(mf_rule) to form the filter rule
 * the format of the rule to write to the proc file is below:
 * %u     %s     %s          %s       %s      %s           %s        %u    %u
 * in_out src_ip src_netmask src_port dest_ip dest_netmask dest_port proto action
 */
void send_rule_to_proc()
{
    FILE *pf;
    const size_t buffer_size = 512;
    char buffer[buffer_size];
    char a_rule[200];
    sprintf(a_rule,"%u %s %s %s %s %s %s %u %u\n", mf_rule.in_out + 1\
            , print_value(mf_rule.src_ip), print_value(mf_rule.src_netmask)\
            , print_value(mf_rule.src_port), print_value(mf_rule.dest_ip)\
            , print_value(mf_rule.dest_netmask), print_value(mf_rule.dest_port)\
            , get_proto(mf_rule.proto),get_action(mf_rule.action));
    send_to_proc(a_rule);
    pf = fopen("/proc/swaruardfirewall","r");
    if(pf == NULL)
    {
        fputs("Cannot open the /proc/swaruardfirewall for writing.\n",stderr);
        exit(1);
    }
    else
    {
        printf("Rules from kernel.\n");
        while(fgets(buffer, buffer_size, pf))
            printf("%s\n",buffer);
        
    }
    fclose(pf);
    return ;
}



/**
 * to form a delete command and write to the proc file
 * ATTENTION: the proc file will be read to reform the filter policy
 * use the static var(mf_delete) to form the delete command
 */
void send_delete_to_proc()
{
    char delete_cmd[20];
    sprintf(delete_cmd, "%s%s\n", "d", print_value(mf_delete.row));
    printf("delete command:%s\n",delete_cmd);
    send_to_proc(delete_cmd);
}



/**
 * print the rules wchich are stored in the proc file
 */
void print_rule()
{
    FILE *pf;
    char token[20];
    char ch;
    int i = 0;
    int rule_index = 0;
    pf = fopen("/proc/swaruardfirewall","r");
    if(pf == NULL)
    {
        fputs("Cannot open /proc/swarurardfirewall for read.\n",stderr);
        exit(1); 
    }
    else
    {
        while(1)
        {
            while(((ch = fgetc(pf)) == ' ') || (ch == '\n'))
            {
                //skip the NULL line and blank in the left
            }
            if(ch == EOF) break;

            //printf the rule's index
            rule_index++;
            printf("rule_index: %d\n",rule_index);

            //1.in or out
            i = 0;
            token[i++] = ch;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            printf("in or out: %s\n",token);
            if(ch == EOF) break;

            //2.src_ip
            i = 0;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            if(strcmp(token,"-") == 0)
            {
                printf("src_ip: %s\n",token);
            }
            else
            {
                printf("src_ip: %s\n",token);
            }

            //3.src_netmask
            i = 0;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            if(strcmp(token,"-") == 0)
            {
                printf("src_netmask: %s\n",token);
            }
            else
            {
                printf("src_netmask: %s\n",token);
            }
            if(ch == EOF) break;

            //4.src_port
            i = 0;
            //token[i++] = ' ';
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            if(strcmp(token,"-") == 0)
            {
                printf("src_port: %s\n",token);
            }
            else
            {
                printf("srd_port: %s\n",token);
            }
            if(ch == EOF) break;

            //5.dest_ip
            i = 0;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            if(strcmp(token,"-") == 0)
            {
                printf("dest_ip:%s\n",token);
            }
            else
            {
                printf("dest_ip:%s\n",token);
            }
            if(ch == EOF) break;

            //6.dest_netmask
            i = 0;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = ch;
            if(strcmp(token,"-") == 0)
            {
                printf("dest_netmask: %s\n",token);
            }
            else
            {
                printf("dest_netmask: %s\n",token);
            }
            if(ch == EOF) break;

            //7.dest_port
            i = 0;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            if(strcmp(token,"-") == 0)
            {
                printf("dest_port: %s\n",token);
            }
            else
            {
                printf("dest_port: %s\n",token);
            }
            if(ch == EOF) break;

            //8.proto
            i = 0;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            if(strcmp(token,"-") == 0)
            {
                printf("proto: %s\n",token);
            }
            else
            {
                printf("proto: %s\n",token);
            }
            if(ch == EOF) break;

            //9.action
            i = 0;
            while(((ch = fgetc(pf)) != EOF) && (ch != ' '))
            {
                token[i++] = ch;
            }
            token[i] = '\0';
            printf("action: %s\n",token);
            if(ch == EOF) break;
        }
    }
    fclose(pf);
    return ;
}


void print_info()
{
    if(mf_rule.in_out == 0)
        printf("Destination:in\n");
    else
        printf("Destination:out\n");
    if(mf_rule.src_ip)
        printf("Src_ip:%s\n",mf_rule.src_ip);
    if(mf_rule.src_netmask)
        printf("Src_netmask:%s\n",mf_rule.src_netmask);
    if(mf_rule.src_port)
        printf("Src_port:%s\n",mf_rule.src_port);
    if(mf_rule.dest_ip)
        printf("Dest_ip:%s\n",mf_rule.dest_ip);
    if(mf_rule.dest_netmask)
        printf("Dest_netmask:%s\n",mf_rule.dest_netmask);
    if(mf_rule.dest_port)
        printf("Dest_port:%s\n",mf_rule.dest_port);
    if(mf_rule.proto)
        printf("Proto:%s\n",mf_rule.proto);
    if(mf_rule.action)
        printf("Action:%s\n",mf_rule.action);
}



/*
 * read the rules store in the rules file
 * file_path: the rules_file's path
 */
void read_rules(const char *file_path)
{
    FILE *rules_file = fopen(file_path, "r");
    const size_t MAX_BUFFER_SIZE = 1024;
    char buffer[MAX_BUFFER_SIZE];
    if(!rules_file)
    {
        fputs("Can not open the rules_file.\n",stderr);
        exit(1);
    }
    while(fgets(buffer, MAX_BUFFER_SIZE, rules_file) != NULL)
    {
        add_rule_command(buffer);
        send_rule_to_proc();
    }
    fclose(rules_file);
}


void add_rule_command(const char *buffer)
{
    int i = 0;
    int j = 0;
    const size_t buffer_size = 512;
    char temp_result[buffer_size];
    char *temp_store;
    //1.in_out
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "in") == 0)
    {
        mf_rule.in_out = 0;
    }
    else
        mf_rule.in_out = 1;
    i++;
    j = 0;
    //2.src_ip
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    printf("src ip : %s\n",temp_result);
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store,temp_result);
        mf_rule.src_ip = temp_store;
    }
    else
        mf_rule.src_ip = NULL;
    i++;
    j = 0;
    //3.src_netmask
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store,temp_result);
        mf_rule.src_netmask = temp_store;
    }
    else
        mf_rule.src_ip = NULL;
    i++;
    j = 0;
    //4.src_port
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store, temp_result);
        mf_rule.src_port = temp_store;
    }
    else
        mf_rule.src_port = NULL;
    i++;
    j = 0;
    //5.dest_ip
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store, temp_result);
        mf_rule.dest_ip = temp_store;
    }
    else
        mf_rule.dest_ip = NULL;
    i++;
    j = 0;
    //6.dest_netmask
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store, temp_result);
        mf_rule.dest_netmask = temp_store;
    }
    else
        mf_rule.dest_netmask = NULL;
    i++;
    j = 0;
    //7.dest_port
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store, temp_result);
        mf_rule.dest_port = temp_store;
    }
    else
        mf_rule.dest_port = NULL;
    i++;
    j = 0;
    //8.proto
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store, temp_result);
        mf_rule.proto = temp_store;
    }
    else
        mf_rule.proto = NULL;
    i++;
    j = 0;
    //9.action
    while(buffer[i] != '#')
    {
        temp_result[j] = buffer[i];
        i++;
        j++;
    }
    temp_result[j] = '\0';
    if(strcmp(temp_result, "-"))
    {
        temp_store = (char *)malloc( j + 1);
        strcpy(temp_store, temp_result);
        mf_rule.action = temp_store;
    }
    else
        mf_rule.action = NULL;
}


/**
 * read the configuration file
 * cfg_file: the configuration file to read
 * item: the item should be read in the file
 * for example the cfg_file contains:
 * Project = /home/william/Scan
 * Server = localhost
 * the result of the read_item(cfg_file, "Project") return "/home/william/Scan"
 */
char *read_item(char const *cfg_file, char const *item)
{
    const size_t MAX_BUFFER_SIZE = 2048;
    FILE *fp;
    char buffer[MAX_BUFFER_SIZE];
    char *dest, *result;
    if((fp = fopen(cfg_file, "r") ) == NULL)
    {
        fputs("Can not open the configue file.\n",stderr);
        return NULL;
    }
    while(fgets(buffer, MAX_BUFFER_SIZE, fp) != NULL)
    {
        if(strncmp(item, buffer, strlen(item))==0)
        {
            dest = strstr(buffer, "=") + 2;
            if((result=(char *)malloc(strlen(dest))) == NULL)
            {
                fputs("Malloc error.\n",stderr);
                fclose(fp);
                return NULL;
            }
            size_t length = strlen(dest);
            memcpy(result, dest, length);
            //result = dest;
            result[length - 1] = '\0';
            fclose(fp);
            return (result);
        }
        continue;
    }
    fclose(fp);
    fputs("Can not find the item\n",stderr);
    return NULL;
}



bool compare_string_flag(const char *str1, const char *str2, char flag)
{
    int i = 0;
    while((str1[i] == str2[i]) && str1[i] && str2[i])
    {
        if(str1[i] == flag)
            return true;
        i++;
    }
    return false;
}


char *query_record_time(const char *time, const char *a_record)
{
    char *result;
    int j_count = 6;
    int i = 0;
    int j = 0;
    while(j_count)
    {
        if(a_record[i] == '#')
            j_count--;
        i++;
    }
    if(!time)
        return NULL;
    //1.Year compare
    if(!compare_string_flag(time, &a_record[i],'#'))
        return NULL;
    while(time[j++] != '#');
    while(a_record[i++] != '#');
    if(!time[j])
    {
        result = (char *)malloc( strlen(a_record) + 1);
        if(!result)
        {
            fputs("Malloc error.\n",stderr);
            exit(1);
        }
        strcpy(result, a_record);
        return result;
    }
    //2.Month compare
    if(!compare_string_flag(&time[j], &a_record[i], '#'))
        return NULL;
    while(time[j++] != '#');
    while(a_record[i++] != '#');
    if(!time[j])
    {
        result = (char *)malloc( strlen(a_record) + 1);
        if(!result)
        {
            fputs("Malloc error.\n",stderr);
            exit(1);
        }
        strcpy(result, a_record);
        return result;
    }
    //3.Day compare
    if(!compare_string_flag(&time[j], &a_record[i], '#'))
        return NULL;
    while(time[j++] != '#');
    while(a_record[i++] != '#');
    if(!time[j])
    {
        result = (char *)malloc( strlen(a_record) + 1);
        if(!result)
        {
            fputs("Malloc error.\n",stderr);
            exit(1);
        }
        strcpy(result, a_record);
        return result;
    }
    //4.Hour compare
    if(!compare_string_flag(&time[j], &a_record[i], '#'))
        return NULL;
    result = (char *)malloc( strlen(a_record) + 1);
    if(!result)
    {
        fputs("Malloc error.\n",stderr);
        exit(1);
    }
    strcpy(result, a_record);
    return result;
}

char *query_record_destip(const char *dest_ip, const char *a_record)
{
    char *result;
    int i = 0;
    int j_count = 3;
    while(j_count)
    {
        if(a_record[i++] == '#')
            j_count--;
    }
    if(!compare_string_flag(dest_ip, &a_record[i], '#'))
        return NULL;
    result = (char *)malloc( strlen(a_record) + 1);
    if(!result)
    {
        fputs("Malloc error.\n",stderr);
        exit(1);
    }
    strcpy(result, a_record);
    return result;
}

void query_record(const char *type)
{
    const size_t buffer_size = 1024;
    FILE *record_file;
    char *file_path = read_item("/home/william/Firewall/firewall_user_files/firewall.conf","record_file_path");
    int i = 0;
    char buffer[buffer_size];
    char *result;
    if(!file_path)
    {
        fputs("Cannot read the record file item.\n",stderr);
        exit(1);
    }
    record_file = fopen(file_path, "r");
    if(!record_file)
    {
        fputs("Fopen error.\n",stderr);
        exit(1);
    }
    //1.ALL
    if(type[0] == 'A')
    {
        while(fgets(buffer, buffer_size, record_file))
            printf("ALL: %s\n",buffer);
    }
    //2.IP
    else if(type[0] == 'I')
    {
        while(type[i++] != '#');
        if(!type[i])
        {
            printf("Lack of IP address.\n");
            fclose(record_file);
            return ;
        }
        while(fgets(buffer, buffer_size, record_file))
        {
            result = query_record_destip(&type[i], buffer);
            if(result)
            {
                printf("IP: %s\n",result);
                free(result);
            }
        }
    }
    else if(type[0] == 'T')
    {
        while(type[i++] != '#');
        if(!type[i])
        {
            printf("Lack of time.\n");
            fclose(record_file);
            return ;
        }
        while(fgets(buffer, buffer_size, record_file))
        {
            result = query_record_time(&type[i], buffer);
            if(result)
            {
                printf("TIME: %s\n",result);
                free(result);
            }
        }
    }
    else
        printf("Error query command.\n");
    fclose(record_file);
}

void clear_all_record()
{
    FILE *record_file;
    char *file_path = read_item("/home/william/Firewall/firewall_user_files/firewall.conf","record_file_path");
    if(!file_path)
    {
        fputs("The record_file_path is missing.\n",stderr);
        exit(1);
    }
    record_file = fopen(file_path, "w");
    if(!record_file)
    {
        fputs("Fopen error.\n",stderr);
        exit(1);
    }
    fclose(record_file);
    return ;
}

/*
 * spy the user's input to figure out the command
 */
void spy_user_input()
{
    const size_t buffer_size = 512;
    char buffer[buffer_size];
    char *temp_result;
    printf("Please input your command.\n");
    fgets(buffer, buffer_size, stdin);
    //add a rule
    if(strncmp(buffer, "add", 3) == 0)
    {
        add_rule_command(&buffer[4]);
        send_rule_to_proc();
        print_info();
    }
    //delete a rule
    else if(strncmp(buffer, "del", 3) == 0)
    {
        temp_result = (char *)malloc(strlen(&buffer[4]) + 1);
        if(!temp_result)
        {
            fputs("Malloc error.\n",stderr);
            exit(1);
        }
        strcpy(temp_result, &buffer[4]);
        mf_delete.row = temp_result;
        temp_result = (char *)malloc(strlen("delete") + 1);
        if(!temp_result)
        {
            fputs("Malloc error.\n",stderr);
            exit(1);
        }
        strcpy(temp_result, "delete");
        mf_delete.cmd = temp_result;        
        send_delete_to_proc();
    }
    //query the log information
    else if(strncmp(buffer, "query", 5) == 0)
    {
    }
    else
        fputs("Command error.\n",stderr);
}


/**
 * the optarg store the argument that you input
 */
int main(int argc, char **argv)
{
    int state;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int sock_fd, retval;
    int state_smg = 0;
    //int c;
    //int action = 1;
    mf_rule.in_out = -1;
    mf_rule.src_ip = NULL;
    mf_rule.src_netmask = NULL;
    mf_rule.src_port = NULL;
    mf_rule.dest_ip = NULL;
    mf_rule.dest_netmask = NULL;
    mf_rule.dest_port = NULL;
    mf_rule.proto = NULL;
    mf_rule.action = NULL;
#if 0
    while(1)
    {
        static struct option long_options[] = 
        {
            {"in",no_argument,&mf_rule.in_out,0},
            {"out",no_argument,&mf_rule.in_out,1},
            {"print",no_argument,0,'o'},
            {"delete",required_argument,0,'d'},
            {"scrip",required_argument,0,'s'},
            {"srcnetmask",required_argument,0,'m'},
            {"srcport",required_argument,0,'p'},
            {"destip",required_argument,0,'t'},
            {"destnetmask",required_argument,0,'n'},
            {"destport",required_argument,0,'q'},
            {"proto",required_argument,0,'c'},
            {"action",required_argument,0,'a'},
            {0,0,0,0}
        };
        int option_index = 0;
        c = getopt_long(argc,argv,"od:s:m:p:t:n:q:c:a:",long_options,&option_index);
        if(c == -1)
            break;
        action = 1;
        switch(c)
        {
            case 0:
                break;
            case 'o':
                action = 2;
                break;
            case 'd':
                action = 3;
                mf_delete.cmd = (char *)long_options[option_index].name;
                mf_delete.row = optarg;
                break;
            case 's':
                mf_rule.src_ip = optarg;
                break;
            case 'm':
                mf_rule.src_netmask = optarg;
                break;
            case 'p':
                mf_rule.src_port = optarg;
                break;
            case 't':
                mf_rule.dest_ip = optarg;
                break;
            case 'n':
                mf_rule.dest_netmask = optarg;
                break;
            case 'q':
                mf_rule.dest_port = optarg;
                break;
            case 'c':
                mf_rule.proto = optarg;
                break;
            case 'a':
                mf_rule.action = optarg;
                break;
            case '?':
                break;
            default:
                abort();
        }
    }
    if(action == 1)
    {
        send_rule_to_proc();
    }
    else if(action == 2)
    {
        print_rule();
    }
    else if(action == 3)
    {
        send_delete_to_proc();
    }
    if(optind < argc)
    {
        while(optind < argc)
            putchar('\n');
    }
#endif

    read_rules("/home/william/Firewall/firewall_user_files/rules.txt");
#if 0
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_REALNET);
    if(sock_fd == -1)
    {
        fputs("Socket error.\n",stderr);
        return -1;
    }
    memset(&msg, 0, sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    retval = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if(retval < 0)
    {
        fputs("Bind error.\n",stderr);
        close(sock_fd);
        return -1;
    }
    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh)
    {
        fputs("Malloc error.\n",stderr);
        close(sock_fd);
        return -1;
    }
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh), "Hello, I am user!");
    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    state_smg = sendmsg(sock_fd, &msg, 0);
    if(state_smg == -1)
    {
        fputs("Sendmsg error.\n",stderr);
        return -1;
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    printf("Waiting for received...\n");
    while(1)
    {
        state = recvmsg(sock_fd, &msg, 0);
        if(state < 0)
        {
            fputs("Recv error.\n",stderr);
            return -1;
        }
        write_record("/home/william/Firewall/firewall_user_files/records.txt",(char *)NLMSG_DATA(nlh));
        printf("Received message:%s\n",(char *)NLMSG_DATA(nlh));
    }
    close(sock_fd);
#endif
    while(1)
    {
        spy_user_input();
    }
    return 0;
}
