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
#include <unistd.h>
#include <setjmp.h>
#include <time.h>
#include <math.h>
#include "sha.h"
#include <errno.h>

// #define RTT 0.2
#define BUFLEN 1500
#define DATA_SIZE 1400
#define SLIDE_WINDOW 8
#define COLLAPSE_TIME 60 //peer is considered collapsed if not receive information for 60s

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

struct chunk_peer_pair_t
{
    char chunk[20];
    struct sockaddr_in peers[30];
    int index; // index of peers
    int id;
    int completed; // 0 no connection,1 completed, 2 receive but not completed;
};

struct peer_t
{
    struct sockaddr_in from;
    int state; // state = 0 no connection, state = 1 connected
    clock_t timer;
    int duplicate;
    char chunk[20];
    int id;
    int type;                        // type 0 receive, type 1 send
    long offset;                     //use to record the offset of file pointer;
    unsigned int next_pack_expected; // type = 0 and decide the ack num
    unsigned int LastPacketAcked;
    unsigned int LastPacketSent;
    unsigned int LastPacketAvailable;
};

static struct peer_t g_connection[30];
static int g_connected = 0;
static int max_connected;

static struct chunk_peer_pair_t g_chunks[20];
static int g_chunkNum = 0;
static int g_hasChunkIndex = 0;

static int con_num = 0;
char chunkfileName[128];

static char g_outputfile[128];
static char g_chunkfile[128];
static char g_datafile[128];
static double RTT = 0;

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
    // use hash to test if receiver has completed
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

int receive_and_send_ack(int sock, struct peer_t *connection, char *outputfile, data_packet_t *curr)
{
    FILE *fp = fopen(outputfile, "r+");
    if (fseek(fp, connection->offset, SEEK_SET))
    {
        perror("can't set the file pointer");
    }

    socklen_t fromlen = sizeof(struct sockaddr_in);
    if (curr->header.packet_type == 3)
    {
        if ((ntohl(curr->header.seq_num)) == connection->next_pack_expected)
        {
            size_t size = ntohs(curr->header.packet_len) - 16;
            int n = fwrite(curr->data, sizeof(char), size, fp);
            connection->next_pack_expected++;
            connection->offset = (int)ftell(fp);
        }
        send_ack(sock, connection->next_pack_expected - 1, connection->from, fromlen);
    }
    fclose(fp);
    if (connection->offset == (connection->id + 1) * BT_CHUNK_SIZE)
    {
        completed(connection->id, g_outputfile, connection->chunk);
        return 1;
    }
    return 0;
}

int get(char *hash, struct sockaddr_in from, int sock, int id, char *outputfile)
{
    struct sockaddr_in recv_from;

    get_pack_t get_pack;

    int flag = 0; // if denied

    // make get_pack
    get_pack.header.magicnum = htons(15441);
    get_pack.header.version = 1;
    get_pack.header.packet_type = 2;
    get_pack.header.header_len = htons(16);

    memcpy(get_pack.chunk, hash, 20);
    get_pack.header.packet_len = htons(36);

    socklen_t recv_fromlen = sizeof(recv_from);
    int retval;
    char buf[BUFLEN];
    clock_t start = clock();
    clock_t now;
    int retans_num = 0;
    spiffy_sendto(sock, &get_pack, sizeof(get_pack_t), 0, (struct sockaddr *)&from, sizeof(from));
    while (1)
    {
        now = clock();
        if ((now - start) / CLOCKS_PER_SEC >= 1)
        {
            retans_num++;
            spiffy_sendto(sock, &get_pack, sizeof(get_pack_t), 0, (struct sockaddr *)&from, (socklen_t)sizeof(from));
            start = clock();
        }
        if (retans_num > 3)
        {
            // retansimit get_pack for more than 3 times, than think peer is collapsed
            return 0;
        }

        retval = spiffy_recvfrom(sock, buf, BUFLEN, MSG_DONTWAIT, (struct sockaddr *)&recv_from, &recv_fromlen);
        if (retval && recv_from.sin_port == from.sin_port && recv_from.sin_addr.s_addr == from.sin_addr.s_addr)
        {
            if (buf[3] == 3)
            {
                break;
            }
            else if (buf[3] == 5)
            {
                flag = 1;
            }
        }
    }
    // calculate the RTT
    now = clock();
    RTT = RTT > (double)(now - start) / CLOCKS_PER_SEC ? RTT : (double)(now - start) / CLOCKS_PER_SEC;

    if (!flag)
    {
        for (int i = 0; i < max_connected; i++)
        {
            if (g_connection[i].state == 0)
            {
                bzero(&g_connection[i], sizeof(g_connection[i]));
                g_connection[i].from = recv_from;
                memcpy(g_connection[i].chunk, hash, 20);
                g_connection[i].state = 1;
                g_connection[i].id = id;
                g_connection[i].timer = clock();
                g_connection[i].type = 0;
                g_connection[i].offset = id * BT_CHUNK_SIZE;
                g_connection[i].next_pack_expected = 1;
                return 1;
            }
        }
    }
    return 0;
}

unsigned int send_all_data_pack(int sock, unsigned int seq, struct peer_t *connection)
{
    FILE *fp = fopen(g_datafile, "r");
    char buffer[BUFLEN];
    unsigned int LastPacketSent;
    int max_seq = (int)ceil((double)BT_CHUNK_SIZE / DATA_SIZE);
    LastPacketSent = max_seq < connection->LastPacketAvailable ? max_seq : connection->LastPacketAvailable;
    for (unsigned int i = seq + 1; i <= LastPacketSent; i++)
    {
        int data_size = DATA_SIZE;
        if (i == max_seq)
        {
            data_size = BT_CHUNK_SIZE - DATA_SIZE * (i - 1);
        }
        data_packet_t data_pack;
        data_pack.header.magicnum = htons(15441);
        data_pack.header.version = 1;
        data_pack.header.packet_type = 3;
        data_pack.header.header_len = htons(16);
        data_pack.header.seq_num = htonl(i);
        data_pack.header.packet_len = htons(16 + data_size);
        fseek(fp, connection->offset + (i - connection->LastPacketAcked - 1) * DATA_SIZE, SEEK_SET);
        fread(buffer, sizeof(char), data_size, fp);
        memcpy(data_pack.data, buffer, data_size);
        spiffy_sendto(sock, &data_pack, sizeof(data_packet_t), 0, (struct sockaddr *)&connection->from, (socklen_t)sizeof(connection->from));
    }
    return LastPacketSent;
    fclose(fp);
}

void send_data_pack(int sock, unsigned int seq, struct peer_t *connection)
{
    connection->LastPacketAvailable = connection->LastPacketAcked + SLIDE_WINDOW;
    connection->LastPacketSent = send_all_data_pack(sock, seq, connection);
    connection->timer = clock();
}

void send_denied_pack(int sock, struct sockaddr_in from)
{
    denied_pack_t denied_pack;
    denied_pack.header.magicnum = htons(15441);
    denied_pack.header.version = 1;
    denied_pack.header.packet_type = 5;
    denied_pack.header.header_len = htons(16);
    denied_pack.header.packet_len = htons(16);
    spiffy_sendto(sock, &denied_pack, sizeof(denied_pack_t), 0, (struct sockaddr *)&from, sizeof(from));
}

void send_data(int sock, struct sockaddr_in from, bt_config_t *config, get_pack_t *get_pack)
{
    FILE *fp = fopen(config->chunk_file, "r");
    char datafile[128];
    fscanf(fp, "File: %s\n", datafile);
    strcpy(g_datafile, datafile);

    int id;
    char ascii_hash[2 * SHA1_HASH_SIZE + 1];
    char recv_hash[2 * SHA1_HASH_SIZE + 1];
    fscanf(fp, "Chunks:\n");
    hex2ascii(get_pack->chunk, SHA1_HASH_SIZE, recv_hash);
    while (fscanf(fp, "%d %s\n", &id, ascii_hash) != EOF)
    {
        if (strcmp(recv_hash, ascii_hash) == 0)
        {
            for (int i = 0; i < max_connected; i++)
            {
                if (g_connection[i].state == 0 || g_connection[i].state == 2)
                {
                    g_connection[i].LastPacketAcked = 0;
                    g_connection[i].LastPacketSent = 0;
                    g_connection[i].from = from;
                    g_connection[i].state = 1;
                    g_connection[i].type = 1;
                    g_connection[i].offset = id * BT_CHUNK_SIZE;
                    memcpy(g_connection[i].chunk, get_pack->chunk, SHA1_HASH_SIZE);
                    g_connection[i].duplicate = 0;
                    g_connection[i].id = id;
                    g_connection[i].timer = clock();
                    send_data_pack(sock, g_connection[i].LastPacketAcked, &g_connection[i]);
                    break;
                }
            }
            break;
        }
    }

    fclose(fp);
}

void build_new_get_connection(int sock)
{
    for (int i = 0; i < max_connected; i++)
    {
        if (g_connection[i].state != 1)
        {
            for (int j = 0; j < g_chunkNum; j++)
            {
                if (g_chunks[j].completed == 0 && g_connected < max_connected)
                {
                    for (int k = 0; k < g_chunks[j].index; k++)
                    {
                        if ((!if_connected(g_chunks[j].peers[k])) && get(g_chunks[j].chunk, g_chunks[j].peers[k], sock, g_chunks[j].id, g_outputfile))
                        {
                            g_connected++;
                            g_chunks[j].completed = 2;
                            break;
                        }
                    }
                }
            }
        }
    }
}

void process_inbound_udp(int sock, bt_config_t *config)
{
    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN];

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);
    // printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
    //        "Incoming message from %s:%d\n\n\n",
    //        inet_ntoa(from.sin_addr),
    //        ntohs(from.sin_port));

    switch (buf[3])
    {
    case 0:
    {
        // receive WHOHAS and send IHAVE
        WHOHAS_pack_t *curr;
        curr = (WHOHAS_pack_t *)buf;
        send_IHAVE_pack(sock, from, config, curr);
        break;
    }
    case 2:
    {
        // receive get and send data
        get_pack_t *curr;
        curr = (get_pack_t *)buf;
        if (g_connected < max_connected)
        {
            send_data(sock, from, config, curr);
            g_connected++;
        }
        else
        {
            send_denied_pack(sock, from);
        }

        break;
    }
    case 3:
    {
        // receive data packet and send ack
        data_packet_t *curr;
        curr = (data_packet_t *)buf;
        for (int i = 0; i < max_connected; i++)
        {
            if (g_connection[i].state == 1 && g_connection[i].type == 0 && ntohs(g_connection[i].from.sin_port) == ntohs(from.sin_port) && ntohl(g_connection[i].from.sin_addr.s_addr) == ntohl(from.sin_addr.s_addr))
            {
                if (receive_and_send_ack(sock, &g_connection[i], g_outputfile, curr))
                {
                    g_connection[i].state = 0; // if completed close connection get new chunk
                    g_connected--;
                    for (int j = 0; j < g_chunkNum; j++)
                    {
                        if (g_chunks[j].id == g_connection[i].id)
                        {
                            g_chunks[j].completed = 1;
                        }
                    }
                    build_new_get_connection(sock);
                }
            }
        }
        break;
    }
    case 4:
    {
        //receive ack
        ack_packet_t *curr;
        curr = (ack_packet_t *)buf;
        for (int i = 0; i < max_connected; i++)
        {
            if (g_connection[i].state == 1 && g_connection[i].type == 1 && ntohs(g_connection[i].from.sin_port) == ntohs(from.sin_port) && ntohl(g_connection[i].from.sin_addr.s_addr) == ntohl(from.sin_addr.s_addr))
            {
                if (g_connection[i].LastPacketAcked == ntohl(curr->header.ack_num))
                {
                    g_connection[i].duplicate++;
                    if (g_connection[i].duplicate == 3)
                    {
                        g_connection[i].duplicate = 0;
                        send_data_pack(sock, g_connection[i].LastPacketAcked, &g_connection[i]);
                        g_connection[i].timer = clock();
                    }
                }
                else if ((int)g_connection[i].LastPacketAcked < (int)ntohl(curr->header.ack_num))
                {
                    g_connection[i].LastPacketAcked = ntohl(curr->header.ack_num);
                    g_connection[i].duplicate = 0;
                    g_connection[i].offset = BT_CHUNK_SIZE * g_connection[i].id + g_connection[i].LastPacketAcked * DATA_SIZE;
                    if (g_connection[i].LastPacketAcked == (int)ceil((double)BT_CHUNK_SIZE / DATA_SIZE)) // send all data
                    {
                        g_connection[i].state = 0;
                        g_connected--;
                        break;
                    }
                    else
                    {
                        send_data_pack(sock, g_connection[i].LastPacketSent, &g_connection[i]);
                    }
                }
            }
        }
        break;
    }
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

void send_WHOHAS_request(char *chunkfile, int sock, bt_config_t *config)
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

int if_connected(struct sockaddr_in from)
{
    for (int i = 0; i < max_connected; i++)
    {
        if (g_connection[i].from.sin_addr.s_addr == from.sin_addr.s_addr && g_connection[i].from.sin_port == from.sin_port && g_connection[i].state == 1)
        {
            return 1;
        }
    }

    return 0;
}

void receive_IHAVE_pack(int sock)
{
    char buf[BUFLEN];
    int n;
    int i, j, chunk_num;
    struct sockaddr_in from;
    socklen_t fromlen;
    fromlen = sizeof(from);
    //use 5 seconds to collect have_pack;
    time_t start = time(NULL);
    time_t now = time(NULL);
    while (difftime(now, start) <= 5.0)
    {
        n = spiffy_recvfrom(sock, buf, BUFLEN, MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
        if (n > 0)
        {
            IHAVE_pack_t *curr;
            curr = (IHAVE_pack_t *)buf;
            switch (curr->header.packet_type)
            {
            case 1:
            {
                chunk_num = curr->chunk_num;
                //collect have_pack and assign each hash peers;
                int flag = 0;
                for (i = 0; i < chunk_num; i++)
                {
                    for (j = 0; j < g_chunkNum; j++)
                    {
                        char ascii_chunk_have[2 * SHA1_HASH_SIZE + 1];
                        char ascii_chunk_receive[2 * SHA1_HASH_SIZE + 1];
                        hex2ascii(g_chunks[j].chunk, SHA1_HASH_SIZE, ascii_chunk_have);
                        hex2ascii(curr->chunks[i], SHA1_HASH_SIZE, ascii_chunk_receive);

                        if (strcmp(ascii_chunk_have, ascii_chunk_receive) == 0)
                        {
                            g_chunks[j].peers[g_chunks[j].index] = from;
                            g_chunks[j].index++;
                            flag = 1;
                        }
                    }
                    if (!flag)
                    {
                        memcpy(g_chunks[g_chunkNum].chunk, curr->chunks[i], SHA1_HASH_SIZE);
                        g_chunks[g_chunkNum].peers[g_chunks[g_chunkNum].index] = from;
                        g_chunks[g_chunkNum].index++;
                        if (g_chunks[g_chunkNum].completed != 1 && g_chunks[g_chunkNum].completed != 2)
                        {
                            g_chunks[g_chunkNum].completed = 0;
                            g_chunkNum++;
                        }
                    }
                    flag = 0;
                }
            }
            default:
                break;
            }
        }
        now = time(NULL);
    }
}

void process_get(char *chunkfile, char *outputfile, bt_config_t *config, int sock)
{
    printf("PROCESS GET SKELETON CODE CALLED yes.  Fill me in!  (%s, %s)\n",
           chunkfile, outputfile);
    // todo
    strcpy(g_chunkfile, chunkfile);
    strcpy(g_outputfile, outputfile);
    send_WHOHAS_request(chunkfile, sock, config);

    receive_IHAVE_pack(sock);

    // create file
    FILE *out_put = fopen(outputfile, "w");
    char output_buf[BT_CHUNK_SIZE * g_chunkNum];
    memset(output_buf, 1, BT_CHUNK_SIZE * g_chunkNum);
    fwrite(output_buf, sizeof(char), BT_CHUNK_SIZE * g_chunkNum, out_put);
    fclose(out_put);

    FILE *fp = fopen(chunkfile, "r");
    assert(fp != NULL);

    int id;
    char chunk_hash[2 * SHA1_HASH_SIZE + 1];
    char hash[20];

    //assign id and start get
    while (fscanf(fp, "%d %s\n", &id, chunk_hash) != EOF && g_connected < max_connected)
    {
        ascii2hex(chunk_hash, strlen(chunk_hash), hash);
        for (int i = 0; i < g_chunkNum; i++)
        {
            char ascii_get_chunk[2 * SHA1_HASH_SIZE + 1];
            hex2ascii(g_chunks[i].chunk, SHA1_HASH_SIZE, ascii_get_chunk);
            if (strcmp(chunk_hash, ascii_get_chunk) == 0)
            {
                g_chunks[i].id = id;
                for (int j = 0; j < g_chunks[i].index; j++)
                {
                    if ((!if_connected(g_chunks[i].peers[j])) && get(hash, g_chunks[i].peers[j], sock, id, outputfile))
                    {
                        g_chunks[i].completed = 2;
                        g_connected++;
                        break;
                    }
                }
            }
        }
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

void resend(int sock, bt_config_t *config)
{
    send_WHOHAS_request(g_chunkfile, sock, config);
    receive_IHAVE_pack(sock); // change g_chunk state;
}

void peer_run(bt_config_t *config)
{
    max_connected = config->max_conn;
    bzero(g_chunks, sizeof(struct chunk_peer_pair_t) * 20);
    bzero(g_connection, sizeof(struct peer_t) * 30);
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
        clock_t now = clock();
        int nfds;
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        struct timeval time;
        time.tv_sec = 0;
        time.tv_usec = 0;
        nfds = select(sock + 1, &readfds, NULL, NULL, &time);

        for (int i = 0; i < max_connected; i++)
        {
            // check timer and retransmit
            if (g_connection[i].state == 1 && g_connection[i].type == 1 && ((now - g_connection[i].timer) / CLOCKS_PER_SEC > RTT))
            {
                send_data_pack(sock, g_connection[i].LastPacketAcked, &g_connection[i]);
                g_connection[i].timer = clock();
            }
            // collapse and resend whohas;
            if (g_connection[i].state == 1 && g_connection[i].type == 0 && ((now - g_connection[i].timer) / CLOCKS_PER_SEC > COLLAPSE_TIME))
            {
                g_connection[i].state = 0;
                g_connected--;
                for (int j = 0; i < g_chunkNum; i++)
                {
                    char connection_hash[2 * SHA1_HASH_SIZE + 1];
                    char chunk_hash[2 * SHA1_HASH_SIZE + 1];
                    hex2ascii(g_connection[i].chunk, SHA1_HASH_SIZE, connection_hash);
                    hex2ascii(g_chunks[j].chunk, SHA1_HASH_SIZE, chunk_hash);
                    if (strcmp(connection_hash, chunk_hash) == 0)
                    {
                        g_chunks[j].completed = 0;
                    }
                }
                resend(sock, config);
                build_new_get_connection(sock);
            }
        }

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
