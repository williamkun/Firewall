/*
 * The command program spys the input of the user
 */
#ifndef COMMAND_H
#define COMMAND_H

#include <stdio.h>

#define print_value(x) (x == NULL ? "-" : x)
typedef enum{ false = 0, true = !false} bool;

struct mf_rule_struct
{
    int in_out;
    char *src_ip;
    char *src_netmask;
    char *src_port;
    char *dest_ip;
    char *dest_netmask;
    char *dest_port;
    char *proto;
    char *action;
};

struct mf_delete_struct
{
    char *cmd;
    char *row;
};

/*
 * send a command to the kernel
 * str: delete command or add command
 */
void send_to_proc(const char *str);

/*
 * get the proto
 * proto: the protocol(TCP UDP ALL)
 * return value:
 * 0:ALL
 * 1:TCP
 * 2:UDP
 * -1:ERROR
 */
int get_proto(const char *proto);

/*
 * get the action
 * action: the action of the rule(BLOCK UNBLOCK)
 * return value:
 * 0: BLOCK
 * 1: UNBLOCK
 */
int get_action(const char *action);

/*
 * send the static mf_rule to the proc, it's the add commmand
 * return value: NULL
 */
void send_rule_to_proc();

/*
 * send the static mf_delete to the proc, it's the delete command
 * reutrn value: NULL
 */
void send_delete_to_proc();

/*
 * print the rules which are store in the proc
 */
void print_rule();

/*
 * print the mf_rule info
 */
void print_info();

/*
 * read all rules which are store in the rules' file
 * file_path: the rules' file path
 * return value: NULL
 */
void read_rules(const char *file_path);

/*
 * figure out the info stored in the buffer and send it to proc
 * buffer: the buffer to be figured
 * return value: NULL
 */
void add_rule_command(const char *buffer);

/*
 * query the record according the the time
 * time: the time you want to query
 * a_record: the record got from the record file
 * return value:
 * succeed: return the record
 * failed: reuturn NULL
 */
char  *query_record_time(const char *time, const char *a_record);

/*
 * query the record according the destip
 * dest_ip: the dest ip you want to query
 * a_record: the record got from the record file
 * return value:
 * succeed: return the record
 * failed: return NULL
 */
char *query_record_destip(const char *dest_ip, const char *a_record);

/*
 * query the record file
 * type: the query type( ALL TIME IP)
 * return value: NULL
 */
void query_record(const char *type);

/*
 * write the mf_rule to the rules' file
 * return value: NULL
 */
void add_a_rule();

/*
 * query rules stored in the rules's file
 * return value: NULL
 */
void query_rules();

/*
 * delete a rule in the rules' file
 * index: the index of the rule in the file
 * return value: NULL
 */
void del_a_rule(unsigned int index);

/*
 * clear all the records which are stored in the record file
 * return value: NULL
 */
void clear_all_record();

/*
 * compare two string according to the flag
 * str1: the src string
 * str2: the dest string
 * flag: the flag to comapre( '#' )
 * return value:
 * true: the same
 * false: not same
 */
bool compare_string_flag(const char *str1, const char *str2, char flag);

/*
 * read the configure file
 * cfg_file: the path of the configure file
 * item: the Key name
 * return value:
 * succeed: the Value of the Key
 * failed: NULL
 */
char *read_item(char const *cfg_file, char const *item);
#endif
