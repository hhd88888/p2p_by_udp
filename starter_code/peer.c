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

void peer_run(bt_config_t *config);

int comp(char *str, WHOHAS_pack_t *curr)
{
    int chunk_num = (ntohs(curr->header.packet_len) - 20) / 20;
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

    while (fscanf(fp, "%d %s\n", &id, chunk_hash) != EOF)
    {
        if (comp(chunk_hash, curr))
        {
            ascii2hex(chunk_hash, strlen(chunk_hash), iHave_pack.chunks[cur]);
            cur += 1;
        }
        if (cur == CHUNK_SIZE)
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

void process_inbound_udp(int sock, bt_config_t *config)
{
#define BUFLEN 1500
    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN];
    WHOHAS_pack_t *curr;

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);
    //recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);

    curr = (WHOHAS_pack_t *)buf;

    printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
           "Incoming message from %s:%d\n%s\n\n",
           inet_ntoa(from.sin_addr),
           ntohs(from.sin_port),
           buf);

    switch (curr->header.packet_type)
    {
    case 0:
        send_IHAVE_pack(sock, from, config, curr);
        break;

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
        //sendto(sock, msg, sizeof(WHOHAS_pack_t), 0, (struct sockaddr *)&(p->addr), sizeof(p->addr));
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

    while (fscanf(fp, "%d %s\n", &id, chunk_hash) != EOF)
    {
        ascii2hex(chunk_hash, strlen(chunk_hash), whoHas_pack.chunks[cur]);
        cur += 1;
        if (cur == CHUNK_SIZE)
        {
            whoHas_pack.chunk_num = CHUNK_SIZE;
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
}

void process_get(char *chunkfile, char *outputfile, int sock, bt_config_t *config)
{
    printf("PROCESS GET SKELETON CODE CALLED yes.  Fill me in!  (%s, %s)\n",
           chunkfile, outputfile);
    // todo
    send_WHOHAS_request(chunkfile, sock, config);
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
            process_get(chunkf, outf, sock, config);
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
