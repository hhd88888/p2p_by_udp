/*
 * peer.c
 * 
 * Author: Yi Lu <19212010040@fudan.edu.cn>,
 *
 * Modified from CMU 15-441,
 * Original Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *                   Dave Andersen
 * 
 * Class: Networks (Spring 2015)
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "package.h"
#include <assert.h>
#include "chunk.h"
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <time.h>
#include <math.h>
#include "sha.h"
#include <errno.h>

#define RTT 1.0
#define BUFLEN 1500
#define DATA_SIZE 1400
#define MAX_JUMPS 3
#define SLIDE_WINDOW 1

static jmp_buf jump_buf; // use to store retransmit state of different connection
static int con_num = 0;
char outputfileName[128];
char chunkfileName[128];

void peer_run(bt_config_t *config);

int main(int argc, char **argv)
{
    bt_config_t config;

    bt_init(&config, argc, argv);

    DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
    config.identity = 1; // your group number here
    strcpy(config.chunk_file, "chunkfile");
    strcpy(config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&config);

#ifdef DEBUG
    if (debug & DEBUG_INIT)
    {
        bt_dump_config(&config);
    }
#endif
    peer_run(&config);
    return 0;
}

// use to store the arrange of hash
struct hash_peer_t
{
    char **chunks;
    int chunk_num;
    struct sockaddr_in from;
};

int comp(char *str, WHOHAS_pack_t *curr)
{
    // to test
    int chunk_num = curr->chunk_num;
    for (int i = 0; i < chunk_num; i++)
    {
        char answer[100];
        hex2ascii(curr->chunks[i], 20, answer);
        if (strcmp(answer, str) == 0)
        {
            return 1;
        }
    }

    return 0;
}

void send_IHAVE_pack(int sock, struct sockaddr_in from, bt_config_t *config, WHOHAS_pack_t *curr)
{
    FILE *fp = fopen(config->has_chunk_file, "r");
    int id;
    int cur = 0;
    char chunk_hash[100];
    IHAVE_pack_t iHave_pack;
    iHave_pack.header.magicnum = htons(15441);
    iHave_pack.header.version = 1;
    iHave_pack.header.packet_type = 1;
    iHave_pack.header.header_len = htons(16);

    //make and send pack;
    while (fscanf(fp, "%d %s\n", &id, chunk_hash) != EOF)
    {
        if (comp(chunk_hash, curr))
        {
            ascii2hex(chunk_hash, strlen(chunk_hash), iHave_pack.chunks[cur]);
            cur += 1;
        }
        if (cur == BT_CHUNK_SIZE)
        {
            iHave_pack.chunk_num = cur;
            iHave_pack.header.packet_len = htons(1500);
            spiffy_sendto(sock, &iHave_pack, sizeof(IHAVE_pack_t), 0, (struct sockaddr *)&from, sizeof(from));
            memset(iHave_pack.chunks, 0, sizeof(iHave_pack.chunks));
            cur = 0;
        }
    }

    if (cur > 0)
    {
        iHave_pack.chunk_num = cur;
        iHave_pack.header.packet_len = htons(cur * 20 + 20);
        spiffy_sendto(sock, &iHave_pack, sizeof(IHAVE_pack_t), 0, (struct sockaddr *)&from, sizeof(from));
    }

    fclose(fp);
}

void sig_alarm(int signo)
{
    siglongjmp(jump_buf, 1);
}

void send_ack(int sock, unsigned int acknum, struct sockaddr_in from, socklen_t fromlen)
{
    ack_packet_t ack_pack;
    ack_pack.header.magicnum = htons(15441);
    ack_pack.header.version = 1;
    ack_pack.header.packet_type = 4;
    ack_pack.header.packet_len = htons(16);
    ack_pack.header.header_len = htons(16);
    ack_pack.header.ack_num = htonl(acknum);

    spiffy_sendto(sock, &ack_pack, sizeof(ack_packet_t), 0, (struct sockaddr *)&from, fromlen);
}

int completed(int id, char *outputfile, uint8_t *hash)
{
    // use hash to test if complete the transfer
    FILE *fp = fopen(outputfile, "r");
    int numbytes;
    uint8_t buffer[BT_CHUNK_SIZE];
    uint8_t file_hash[SHA1_HASH_SIZE];
    char ascii1[2 * SHA1_HASH_SIZE + 1];
    char ascii2[2 * SHA1_HASH_SIZE + 1];
    fseek(fp, id * BT_CHUNK_SIZE, SEEK_SET);
    numbytes = fread(buffer, sizeof(uint8_t), BT_CHUNK_SIZE, fp);

    shahash(buffer, numbytes, file_hash);
    hex2ascii(hash, SHA1_HASH_SIZE, ascii1);
    hex2ascii(file_hash, SHA1_HASH_SIZE, ascii2);

    if (strcmp(file_hash, hash) == 0)
    {
        return 1;
    }
    fclose(fp);
    return 0;
}

void reget(char *hash)
{
    // todo
}

void receive_and_send_ack(int sock, uint8_t *hash, int id, char *outputfile)
{
    FILE *fp = fopen(outputfile, "r+");
    if (fseek(fp, BT_CHUNK_SIZE * id, SEEK_SET))
    {
        perror("can't set the file pointer");
    }
    //signal(SIGALRM, reget(hash, sock));

    unsigned int next_pack_expected = 1;
    unsigned int last_pack_rcvd = 0;
    data_packet_t *data_pack;
    //fseek(fp, id * BT_CHUNK_SIZE, SEEK_SET);
    char buf[BUFLEN];

    int retval;

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    while ((int)ftell(fp) < (id + 1) * BT_CHUNK_SIZE)
    {
        retval = spiffy_recvfrom(sock, buf, BUFLEN, MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
        if (retval > 0)
        {
            data_pack = (data_packet_t *)buf;
            if (data_pack->header.packet_type == 3)
            {
                if ((ntohl(data_pack->header.seq_num)) == next_pack_expected)
                {
                    size_t size = ntohs(data_pack->header.packet_len) - 16;
                    int n = fwrite(data_pack->data, sizeof(char), size, fp);
                    next_pack_expected++;
                }
                send_ack(sock, next_pack_expected - 1, from, fromlen);
            }
        }
    }
    fclose(fp);
}

void get(char *hash, struct sockaddr_in from, int sock, int id, char *outputfile)
{
    //new sock;
    //printf("---------------------id:%d_________________________-————————————————————————————————\n", id);
    // int sock;
    // struct sockaddr_in myaddr;

    // if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
    // {
    //     perror("get could not create socket");
    //     exit(-1);
    // }

    // bzero(&myaddr, sizeof(myaddr));
    // myaddr.sin_family = AF_INET;
    // myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    // myaddr.sin_port = htons(port);

    // if (bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr)) == -1)
    // {
    //     perror("get could not bind socket");
    //     exit(-1);
    // }

    struct sockaddr_in recv_from;

    get_pack_t get_pack;

    // make get_pack
    get_pack.header.magicnum = htons(15441);
    get_pack.header.version = 1;
    get_pack.header.packet_type = 2;
    get_pack.header.header_len = htons(16);

    memcpy(get_pack.chunk, hash, 20);
    get_pack.header.packet_len = htons(36);

    spiffy_sendto(sock, &get_pack, sizeof(get_pack_t), 0, (struct sockaddr *)&from, (socklen_t)sizeof(from));

    // user alarm to transmit and go to receive function after receive

    //spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&recv_from, sizeof(recv_from));

    // receive the first pack and this means cennection is constructed
    receive_and_send_ack(sock, hash, id, outputfile);
}

unsigned int send_all_data_pack(int sock, struct sockaddr_in from, unsigned int LastPacketAcked, unsigned int LastPacketAvailable, int data_num, uint8_t *buffer)
{
    unsigned int LastPacketSent = 0;
    int max_seq = (int)ceil((double)data_num / DATA_SIZE);
    LastPacketSent = max_seq < LastPacketAvailable ? max_seq : LastPacketAvailable;
    for (unsigned int i = LastPacketAcked + 1; i <= LastPacketSent; i++)
    {
        int data_size = DATA_SIZE;
        if (i == max_seq)
        {
            data_size = data_num - DATA_SIZE * (i - 1);
        }
        data_packet_t data_pack;
        data_pack.header.magicnum = htons(15441);
        data_pack.header.version = 1;
        data_pack.header.packet_type = 3;
        data_pack.header.header_len = htons(16);
        data_pack.header.seq_num = htonl(i);
        data_pack.header.packet_len = htons(16 + data_size);
        memcpy(data_pack.data, buffer + (i - 1) * DATA_SIZE, data_size);
        spiffy_sendto(sock, &data_pack, sizeof(data_packet_t), 0, (struct sockaddr *)&from, (socklen_t)sizeof(from));
    }
    return LastPacketSent;
}

void send_data_pack(int id, char *datafile, int sock, struct sockaddr_in from)
{
    FILE *fp = fopen(datafile, "r");
    fseek(fp, id * BT_CHUNK_SIZE, SEEK_SET);
    char buffer[BT_CHUNK_SIZE];
    int data_num = fread(buffer, sizeof(uint8_t), BT_CHUNK_SIZE, fp);
    unsigned int LastPacketAcked = 0;
    unsigned int LastPacketSent = 0;
    unsigned int LastPacketAvailable = LastPacketAcked + SLIDE_WINDOW;
    int duplicate_ack = 0;
    ack_packet_t *ack_pack;
    char buf[BUFLEN];
    int retval;

    struct sockaddr_in recvfrom;
    socklen_t recvformlen = sizeof(recvfrom);

    int max_seq = (int)ceil((double)data_num / DATA_SIZE);

    while (LastPacketAcked < max_seq)
    {
        LastPacketSent = send_all_data_pack(sock, from, LastPacketAcked, LastPacketAvailable, data_num, buffer);
        retval = spiffy_recvfrom(sock, buf, BUFLEN, MSG_DONTWAIT, (struct sockaddr *)&recvfrom, &recvformlen);
        if (retval > 0)
        {
            if (buf[3] == 4)
            {
                ack_pack = (ack_packet_t *)buf;

                if (ntohl(ack_pack->header.ack_num) == LastPacketAcked)
                {
                    duplicate_ack++;
                }
                else if (LastPacketAcked < ntohl(ack_pack->header.ack_num))
                {
                    duplicate_ack = 0;
                    LastPacketAcked = ntohl(ack_pack->header.ack_num);
                    LastPacketAvailable = LastPacketSent + SLIDE_WINDOW;
                }

                if (duplicate_ack == 3)
                {
                }
            }
        }
    }
    fclose(fp);
}

void send_data(int sock, struct sockaddr_in from, bt_config_t *config, get_pack_t *get_pack)
{
    FILE *fp = fopen(config->chunk_file, "r");
    char datafile[128];
    fscanf(fp, "File: %s\n", datafile);

    int id;
    char ascii_hash[2 * SHA1_HASH_SIZE + 1];
    char recv_hash[2 * SHA1_HASH_SIZE + 1];
    fscanf(fp, "Chunks:\n");
    hex2ascii(get_pack->chunk, SHA1_HASH_SIZE, recv_hash);
    while (fscanf(fp, "%d %s\n", &id, ascii_hash) != EOF)
    {
        if (strcmp(recv_hash, ascii_hash) == 0)
        {
            send_data_pack(id, datafile, sock, from);
            break;
        }
    }

    fclose(fp);
}

void process_inbound_udp(int sock, bt_config_t *config)
{

    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN];

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);
    //recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);

    printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
           "Incoming message from %s:%d\n%d\n\n",
           inet_ntoa(from.sin_addr),
           ntohs(from.sin_port),
           buf[3]);

    switch (buf[3])
    {
    case 0:
    {
        // to test
        WHOHAS_pack_t *curr;
        curr = (WHOHAS_pack_t *)buf;
        send_IHAVE_pack(sock, from, config, curr);
        break;
    }
    case 2:
    {
        get_pack_t *curr;
        curr = (get_pack_t *)buf;
        send_data(sock, from, config, curr);
    }
    // case 1:
    //     // need to arrange the prot num for different processing
    //     IHAVE_pack_t *curr;
    //     curr = (IHAVE_pack_t *)buf;
    //     chunknum = curr->chunk_num;
    //     while (curr->chunkfile)
    //         get(char* hash, sock, from);
    //     break;
    default:
        break;
    }
}

/*send message to all*/
void send_to_all(int sock, const void *msg, bt_config_t *config)
{
    bt_peer_t *p;
    for (p = config->peers; p != NULL; p = p->next)
    {
        spiffy_sendto(sock, msg, sizeof(WHOHAS_pack_t), 0, (struct sockaddr *)&(p->addr), sizeof(p->addr));
    }
}

int send_WHOHAS_request(char *chunkfile, int sock, bt_config_t *config)
{
    WHOHAS_pack_t whoHas_pack;
    whoHas_pack.header.magicnum = htons(15441);
    whoHas_pack.header.version = 1;
    whoHas_pack.header.packet_type = 0;
    whoHas_pack.header.header_len = htons(16);

    FILE *fp = fopen(chunkfile, "r");
    assert(fp != NULL);

    int cur = 0;

    int id;
    char chunk_hash[100];

    int sum = 0;

    while (fscanf(fp, "%d %s\n", &id, chunk_hash) != EOF)
    {
        ascii2hex(chunk_hash, strlen(chunk_hash), whoHas_pack.chunks[cur]);
        cur += 1;
        sum++;
        if (cur == BT_CHUNK_SIZE)
        {
            whoHas_pack.chunk_num = BT_CHUNK_SIZE;
            whoHas_pack.header.packet_len = htons(1500);
            send_to_all(sock, &whoHas_pack, config);
            memset(whoHas_pack.chunks, 0, sizeof(whoHas_pack.chunks));
            cur = 0;
        }
    }

    if (cur > 0)
    {
        whoHas_pack.chunk_num = cur;
        whoHas_pack.header.packet_len = htons(cur * 20 + 20);
        send_to_all(sock, &whoHas_pack, config);
    }

    fclose(fp);
    return sum;
}

static void intermit(int signo)
{
    return;
}

void process_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock)
{
    printf("PROCESS GET SKELETON CODE CALLED yes.  Fill me in!  (%s, %s)\n",
           chunkfile, outputfile);
    // todo
    bzero(chunkfileName, sizeof(chunkfileName));
    bzero(outputfileName, sizeof(outputfileName));
    strcpy(chunkfileName, chunkfile);
    strcpy(outputfileName, outputfile);
    int packet_num = send_WHOHAS_request(chunkfile, sock, config);
    int chunk_num;
    struct sockaddr_in from;
    struct sockaddr_in recv_from;
    socklen_t fromlen;
    socklen_t recv_from_len;
    WHOHAS_pack_t *curr;

    fromlen = sizeof(from);
    recv_from_len = sizeof(recv_from);

    struct hash_peer_t hash_peer[50];
    for (int i = 0; i < 50; i++)
    {
        hash_peer[i].chunk_num = 0;
    }
    int peer_index = 0;
    int flag = 0;

    //use 5 seconds to collect have_pack;
    time_t start = time(NULL);
    time_t now;

    char buf[BUFLEN];
    int n;
    int i, j;

    while (difftime(now, start) <= 5.0)
    {
        n = spiffy_recvfrom(sock, buf, BUFLEN, MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
        //printf("***&*&^*&^*^*^\n");
        if (n > 0)
        {
            IHAVE_pack_t *curr;
            curr = (IHAVE_pack_t *)buf;
            switch (curr->header.packet_type)
            {
            case 1:
            {
                chunk_num = curr->chunk_num;
                // collect have_pack and try to arrange the peer;
                // for (i = 0; i < peer_index; i++)
                // {
                //     if (ntohs(hash_peer[i].from.sin_port) == ntohs(from.sin_port) && (inet_ntoa(hash_peer[i].from.sin_addr) == inet_ntoa(from.sin_addr)))
                //     {
                //         flag = 1;
                //         for (j = 0; j < chunk_num; j++)
                //         {
                //             memcpy(hash_peer[i].chunks[hash_peer[i].chunk_num], curr->chunks[j], 20);
                //             hash_peer[i].chunk_num++;
                //         }
                //         break;
                //     }
                // }
                // if (!flag)
                // {
                //     printf("hash:%d\n", chunk_num);
                //     for (i = 0; i < chunk_num; i++)
                //     {
                //         printf("%d************", chunk_num);
                //         char result[2*SHA1_HASH_SIZE+1];
                //         hex2ascii(curr->chunks[i], SHA1_HASH_SIZE, result);
                //         printf("hash:%s\n", result);
                //         memcpy(hash_peer[peer_index].chunks[0], curr->chunks[i], 20);
                //         hash_peer[peer_index].chunk_num++;
                //     }
                //     printf("***&*&^*&^*^*^sdadwd\n");
                // }
                // break;

                // we need to add address
                recv_from_len = fromlen;
                recv_from = from;

                // for (i = 0; i < chunk_num; i++)
                // {
                //     printf("%d************", buf[16]);
                //     char result[2*SHA1_HASH_SIZE+1];
                //     hex2ascii(curr->chunks[i], SHA1_HASH_SIZE, result);
                //     printf("hash:%s\n", result);
                // }
            }
            default:
                break;
            }
        }

        now = time(NULL);
    }

    FILE *out_put = fopen(outputfile, "w");
    char output_buf[BT_CHUNK_SIZE * chunk_num];
    memset(output_buf, 1, BT_CHUNK_SIZE * chunk_num);
    fwrite(output_buf, sizeof(char), BT_CHUNK_SIZE * chunk_num, out_put);
    fclose(out_put);

    // need to repair
    FILE *fp = fopen(chunkfile, "r");
    assert(fp != NULL);

    int cur = 0;

    int id;
    char chunk_hash[100];
    char hash[20];

    //to use and check

    while (fscanf(fp, "%d %s\n", &id, chunk_hash) != EOF)
    {
        ascii2hex(chunk_hash, strlen(chunk_hash), hash);
        get(hash, recv_from, sock, id, outputfile);
    }
}

void handle_user_input(char *line, void *cbdata, int sock, bt_config_t *config)
{
    char chunkf[128], outf[128];

    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));

    if (sscanf(line, "GET %120s %120s", chunkf, outf))
    {
        if (strlen(outf) > 0)
        {
            process_get(chunkf, outf, config, sock);
        }
    }
}

void peer_run(bt_config_t *config)
{
    int sock;
    struct sockaddr_in myaddr;
    fd_set readfds;
    struct user_iobuf *userbuf;

    if ((userbuf = create_userbuf()) == NULL)
    {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
    {
        perror("peer_run could not create socket");
        exit(-1);
    }

    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(config->myport);

    if (bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr)) == -1)
    {
        perror("peer_run could not bind socket");
        exit(-1);
    }

    spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

    while (1)
    {
        int nfds;
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        nfds = select(sock + 1, &readfds, NULL, NULL, NULL);

        if (nfds > 0)
        {
            if (FD_ISSET(sock, &readfds))
            {
                process_inbound_udp(sock, config);
            }

            if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                process_user_input(STDIN_FILENO, userbuf, handle_user_input,
                                   "Currently unused", sock, config);
            }
        }
    }
}
