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

void process_inbound_udp(int sock)
{
#define BUFLEN 1500
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];

  fromlen = sizeof(from);
  spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&from, &fromlen);

  printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
         "Incoming message from %s:%d\n%s\n\n",
         inet_ntoa(from.sin_addr),
         ntohs(from.sin_port),
         buf);
}

/*send message to all*/
inline void send_to_all(int sock, const void* msg, bt_config_t *config)
{
  bt_peer_t *p;
  for (p = config->peers; p != NULL; p = p->next)
  {
    spiffy_sendto(sock, msg, sizeof(msg), 0, (struct sockaddr *)&p->addr, sizeof(p->addr));
  }
}

void send_WHOHAS_request(char *chunkfile, int sock, bt_config_t *config)
{
  WHOHAS_pack_t whoHas_pack;
  whoHas_pack.header.magicnum = htons(15441);
  whoHas_pack.header.version = htons(1);
  whoHas_pack.header.packet_type = htons(0);

  FILE *fp = fopen(chunkfile, "r");
  assert(fp != NULL);

  int cur = 0;

  int id;
  char *chunk_hash;

  while (fscanf(fp, "%d %s\n", &id, chunk_hash) != EOF)
  {
    printf("%s", chunk_hash);
    memset(whoHas_pack.chunks, 0, sizeof(whoHas_pack.chunks));
    strcat(whoHas_pack.chunks, chunk_hash);
    cur += 20;
    if (cur == 1480)
    {
      send_to_all(sock,&whoHas_pack,config);
    }
    memset(whoHas_pack.chunks, 0, sizeof(whoHas_pack.chunks));
    cur = 0;
  }

  send_to_all(sock, &whoHas_pack, config);
}

void process_get(char *chunkfile, char *outputfile, int sock, bt_config_t *config)
{
  printf("PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n",
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
        process_inbound_udp(sock);
      }

      if (FD_ISSET(STDIN_FILENO, &readfds))
      {
        process_user_input(STDIN_FILENO, userbuf, handle_user_input,
                           "Currently unused", sock);
      }
    }
  }
}