#ifndef _PACKAGE_H_
#define _PACKAGE_H_

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#define UDP_SIZE 1500

typedef struct header_s
{
  short magicnum;
  char version;
  char packet_type;
  short header_len;
  short packet_len; 
  unsigned int seq_num;
  unsigned int ack_num;
} header_t;

typedef struct data_packet_s
{
    header_t header;
    char data[1400];
} ack_packet_t, data_packet_t;

typedef struct WHOHAS_pack_s
{
    header_t header;
    char chunk_num;
    char padding[3];
    char chunks[74][20];
} WHOHAS_pack_t, IHAVE_pack_t;

typedef struct get_pack_s
{
    header_t header;
    char chunk[20];
} get_pack_t;

typedef struct denied_pack_s
{
    header_t header;
    // something needed to be entered;
} denied_pack_t;



#endif