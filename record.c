#include "record.h"
#include <unistd.h>  
#include <stdlib.h>  
#include <sys/socket.h>
#include <sys/types.h>  
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <sys/stat.h>  
#include <syslog.h>  
#include <signal.h>
#include <time.h>

#define NETLINK_REALNET 26
#define MAX_PAYLOAD 1024

int daemon_init(void)   
{   
    pid_t pid;   
    if((pid = fork()) < 0)   
        return(-1);   
    else if(pid != 0)   
        exit(0); /* parent exit */   
    /* child continues */   
    setsid(); /* become session leader */   
    close(0); /* close stdin */   
    close(1); /* close stdout */   
    close(2); /* close stderr */   
    return(0);   
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

void sig_term(int signo)
{
    if(signo == SIGTERM)
        exit(0);
}


void netlink_comm()
{
    const size_t buffer_size = 512;
    char buffer[buffer_size];
    size_t length = 0;
    int state;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int sock_fd, retval;
    int state_smg = 0;

    time_t now;
    struct tm *tmlocal;

    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_REALNET);
    if(sock_fd == -1)
    {
        exit(1);
    }
    memset(&msg, 0, sizeof(msg));
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    retval = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
    if(retval < 0)
    {
        close(sock_fd);
        exit(1);
    }
    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh)
    {
        close(sock_fd);
        exit(1);
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
        exit(1);
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    while(1)
    {
        state = recvmsg(sock_fd, &msg, 0);
        if(state < 0)
        {
            exit(1);
        }
        time(&now);
        tmlocal = localtime(&now);
        memset(buffer, 0, buffer_size);
        strcpy(buffer, (char *)NLMSG_DATA(nlh));
        length = strlen(buffer);
        sprintf(&buffer[length],"%d#%d#%d#%d#%d#%d#",tmlocal->tm_year, tmlocal->tm_mon\
                , tmlocal->tm_mday,tmlocal->tm_hour, tmlocal->tm_min, tmlocal->tm_sec);
        write_record("/home/william/Firewall/firewall_user_files/records.txt", buffer);
    }
    close(sock_fd);
}

int main(int argc, char *argv[])
{
    int ret = daemon_init();
    signal(SIGTERM, sig_term);
    if(ret == -1)
        exit(1);
    netlink_comm();    
    return 0;
}
