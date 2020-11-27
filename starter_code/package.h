#ifndef _PACKAGE_H_
#define _PACKAGE_H_

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#define UDP_SIZE 1500
#define CHUNK_SIZE 74

typedef struct header_s
{
  short magicnum;
  char version;
  char packet_type;
  short header_len;
  short packet_len; 
  u_int seq_num;
  u_int ack_num;
} header_t;

typedef struct data_body_s
{
    header_t header;
    uint8_t *data;
} ack_packet_t, data_packet_t;

// typedef struct ack_pack_s
// {
//     data_body_t data;
// } ack_packet_t;

// typedef struct data_pack_s
// {
//     data_body data;
// } data_packet_t;

typedef struct WHOHAS_pack_s
{
    header_t header;
    char chunk_num;
    char padding[3];
    uint8_t chunks[74][20];
} WHOHAS_pack_t, IHAVE_pack_t;

// typedef struct WHOHAS_pack_s
// {
//     WHOHAS_body_s_t body;
// } WHOHAS_pack_t;

// typedef struct IHAVE_pack_s
// {
//     WHOHAS_body_s_t body;
// } IHAVE_pack_t;

typedef struct get_pack_s
{
    header_t header;
    uint8_t *chunk;
} get_pack_t;

typedef struct denied_pack_s
{
    header_t header;
    // something needed to be entered;
} denied_pack_t;

#endif