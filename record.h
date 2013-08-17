#ifndef RECORD_H
#define RECORD_H

#include <stdio.h>

void write_record(const char *record_file, const char *packet_info);
int daemon_init(void);
void sig_term(int signo);
void netlink_comm();

#endif
