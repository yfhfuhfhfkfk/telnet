#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/des.h>

#include "my_types.h"
#include "utils.h"
#include "finite_state_machine.h"
#include "fy_crypt.h"

#define SEND_BUF_SIZE 128

/**********
 * 选项支持数组
 * 0 - 不支持
 * 1 - 支持
 * init_if_support()用以初始化
 * ********/
bool if_support[255];
bool if_enable[255];

void init_if_support()
{
    if_support[ECHO] = 1;
}

int server_port = 1234; //服务器端口
sockaddr_in sock_addr;  //服务端套接字网络地址
int fd_server_sock;     //服务端套接字
sockaddr client_addr;   //客户端套接字网络地址
int fd_client_sock;

//检查参数数目及是否为一个合法的ipv4地址
void check_args(int argc, char *argv[])
{
    print_log("参数检查开始");
    if (argc != 1)
    {
        print_error("不需要参数，参数将被忽略");
    }
    print_log("参数检查完成");
}

//初始化套接字
void init_socket()
{
    print_log("初始化网络连接开始");

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = INADDR_ANY;
    sock_addr.sin_port = htons(server_port);

    if ((fd_server_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
        print_error("套接字创建失败");
        exit(-1);
    }

    if (bind(fd_server_sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1)
    {
        print_error("套接字绑定失败");
        exit(-1);
    }

    if (listen(fd_server_sock, 20))
    {
        print_error("开启监听失败");
        exit(-1);
    }

    socklen_t client_addr_size = sizeof(client_addr);
    fd_client_sock = accept(fd_server_sock, (struct sockaddr *)&client_addr, &client_addr_size);

    print_log("初始化网络连接完成");
}

unsigned char private_key[] = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnFPTGC5F+ksqY\n\
pBumAVWtbHImsVTXrT49dhSvs4bacyQMdCoeIxzh8rmokB2BJEhup+KPY9naqRHZ\n\
EOx8Eg2wg7UilbVLqtTdHN/8ZymwHZcEdAOc/SC/J2foHw+n9ceV5ZX/YDPQIxxv\n\
wEEZo3f/BqRnkVu/VJvd8b17LDeCDKQxnwoMCRjD/mozLTn92sHByhWiCZbaO29Z\n\
kXuljYShQgRJePRDnfnRY1RfBdJBtclkW/JAyG7lTbXA91DyRQxrowWFtU/v23ie\n\
EOMcimy1+vZyYBQN3amA3ed47SD23o3KYxo0brvwjk+wsCUUnfu2tCVAm2CyG/7M\n\
klKjA2FXAgMBAAECggEBAKbtJO+IN0BB3+9IZecghjzRj+pgWOdxyjEVe+1ea2hs\n\
iKN4m2uooP6MxjhGY3PWkBcd3BhuJgVzzMUVR29dihfEPn/jGlISxsByTMWbO+cc\n\
aPil/8Ykj0brU8Bw5+9iepij24xczOcxbQOpDGFVFFnShQaEDynEmkTPdANPVdWy\n\
tjuTgKbXPqeQlfa7MIUwWaVRaiaZPxTBjEUsPwTIVKtT1gElCBamP5UVtuntMVR9\n\
7HG6+c3sqOQ/5/t7ovgylUqBPmKI3aUSS46XcnNX62hhLWPRiNe7NX4S4u00Q4j+\n\
qbRaDF9cLhuLbuKrrVq9fxXAVDnr5hkOBaO9NORP2MECgYEA0fBu3cSF2YxSdhcV\n\
Obws2UkVIWBb0Zo15qjlyG+t9ATPHaCgSZBiKtpu6NtBWzDjbYMHv61Qf4XfZHUc\n\
J+h8M130GzMpwraDTJztlHrI3wFKqSSD6RzlS2h6lInNbVDkeap0mZgIA5CxkhOR\n\
zhnAjq4Tr9USeeHPfBE/hlZ2tmkCgYEAy71fiydn00uRYFolZCS2P5d1GdJ4TwpQ\n\
UTDxP1Guu7bkl/lshB6CnVP87YKYFWg/mIvkwOvuNEart3RpC9cbaurIM1vifWu0\n\
COgGatGSY+aXabOFEd3T1E7Ps1WgiRq/P6MdfuaXjlpJ5MQw71AmkFmoCTfsri4S\n\
XmkMqztH4b8CgYBdA1VbU/KpjA4M2/U/eyuzqTl/bB3CI7y10SbdQv2jG25YBg5+\n\
CUY1DkoNSPcP2/0nS+Jm/faoSTvMWkZ7N/mvGHVKh8R8zDgn/W8VVcEhbIUTo2X+\n\
JhtA6a1Fmjg1sp1HeknmswD582V4/sqesbIqhN2cDZ79+RngMhQfBLfb4QKBgQCN\n\
rRl0halwSDtGmkkoE1NcczDuDOq2ZACoBPWtx1pPlIXvnHW2hhTj3JSkgMzLDhwz\n\
MwyWjzmsxnwAbYXiwumA9tTSyhF8j9m428ginatDpwUhbsGZQ/1axJcwKNoinSPi\n\
18XaCfXX+rcpyrgQola+yGnOR0JheQ4y8q/pnqaEtwKBgDf9v9Qu92PEGngEAXri\n\
mjfLDSN2+FFwomYYHSenQgZSlgtxwkZY3NasPjvq/WoV7ly4zg2IbWrtenqYF2bT\n\
R2p2fyGFPRm0XzPu4y3HqpWLgNlEmaPSSS6rqJ/dHqXoVvlMgVfUMS/mvCsyD96H\n\
zw4o6zcy298IYnpiEdkX2qZR\n\
-----END PRIVATE KEY-----";

uchar key[9];
uchar encrypted_key[257];
void process_crypt()
{
    uchar ch;
    int encrypted_key_len = 256;
    int read_len;
    int i = 0;
    while (i < encrypted_key_len)
    {
        if (read_len = recv(fd_client_sock, &ch, 1, 0) > 0)
        {
            encrypted_key[i] = ch;
            i += read_len;
        }
    }
    RSA_private_decrypt(encrypted_key, 256, key, private_key);
}

int master_fd;

void negotiate()
{
}

void process_data(uchar ch)
{
    write(master_fd, &ch, 1); //ch --> master
}

void deal_server_ECHO(uchar verb)
{
}

void deal_server_SGA(uchar verb)
{
}

void deal_server_TERMTYPE(uchar verb)
{
}

void deal_server_ENVIRON(uchar verb)
{
}

void deal_server_LINEMODE(uchar verb)
{
}

void deal_server_NAWS(uchar verb)
{
}

void deal_server_STATUS(uchar verb)
{
}

void deal_server_TSPEED(uchar verb)
{
}

void deal_server_LFLOW(uchar verb)
{
}

void send_server_pass(uchar verb, uchar option)
{
    uchar sendbuf[3];
    sendbuf[0] = IAC;
    sendbuf[1] = verb;
    sendbuf[2] = option;
    send(fd_client_sock, (char *)sendbuf, 3, 0);
}
void deal_server_term_type()
{
}
finite_state_machine_t finite_state_machine;
void init_finite_state_machine()
{
    finite_state_machine_t &fsm = finite_state_machine;
    fsm.process_data = process_data;
    fsm.deal_ECHO = deal_server_ECHO;
    fsm.deal_SGA = deal_server_SGA;
    fsm.deal_TERMTYPE = deal_server_TERMTYPE;
    fsm.deal_ENVIRON = deal_server_ENVIRON;
    fsm.deal_LINEMODE = deal_server_LINEMODE;
    fsm.deal_NAWS = deal_server_NAWS;
    fsm.deal_STATUS = deal_server_STATUS;
    fsm.deal_TSPEED = deal_server_TSPEED;
    fsm.deal_LFLOW = deal_server_LFLOW;
    fsm.send_pass = send_server_pass;
    fsm.send_term_type = deal_server_term_type;
}

void process_recv()
{
    print_log("process_recv开始");
    uchar ch;
    uchar ch_buf[8];
    uchar encrypted_ch[8];
    while (1)
    {
        if (recv(fd_client_sock, encrypted_ch, 8, 0) > 0)
        {
            DES_decrypt(encrypted_ch, ch_buf, key);
            ch = ch_buf[0];
            finite_state_machine(ch);
        }
    }

    print_log("process_recv结束");
}

//master --> stdout
void process_send()
{
    print_log("process_send开始");
    uchar send_buf[SEND_BUF_SIZE];
    int send_len, read_len, send_pos;
    uchar ch;
    uchar ch_buf[8];
    uchar encrypted_ch[8];
    while (1)
    {
        rand_ch_buf(ch_buf, 8);
        while (read(master_fd, &ch, 1) > 0)
        {
            ch_buf[0] = ch;
            DES_encrypt(ch_buf, encrypted_ch, key);
            send(fd_client_sock, encrypted_ch, 8, 0);
        }

        // while (read(master_fd, &ch, 1) > 0)
        //     send(fd_client_sock, &ch, 1, 0);
    }
    print_log("process_send结束");
}

void run_my_login(int master_fd)
{
    grantpt(master_fd);
    unlockpt(master_fd);
    char *slave_name;
    fprintf(stderr, "%s\n", slave_name = ptsname(master_fd));

    std::string cmd = "./my_login";
    cmd = cmd + " <" + slave_name + " >" + slave_name + " 2>&1";
    system(cmd.c_str());
}

int server()
{
    print_log("执行服务端开始");
    init_socket(); //初始化网络连接
    process_crypt();
    negotiate(); //协议协商
    init_finite_state_machine();
    master_fd = open("/dev/ptmx", O_RDWR | O_NONBLOCK);
    run_my_login(master_fd);

    if (fork())
    {
        process_recv();
    }
    else
    {
        process_send();
    }
    close(fd_server_sock);
    close(fd_client_sock);
    print_log("执行服务端完成");

    return 0;
}

int main(int argc, char *argv[])
{
    check_args(argc, argv); //参数检查
    return server();        //执行服务端
}
