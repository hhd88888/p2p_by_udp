#ifndef _PACKAGE_H_
#define _PACKAGE_H_

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#define UDP_SIZE 1500

typedef struct header_s
{
    uint16_t magicnum;
    uint8_t version;
    uint8_t packet_type;
    uint8_t header_len;
    uint8_t packet_len;
    uint32_t seq_num;
    uint32_t ack_num;
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
    uint8_t chunk_num;
    uint8_t padding[3];
    char chunks[UDP_SIZE - 20];
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