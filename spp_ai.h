/*
 * =====================================================================================
 *
 *       Filename:  spp_ai.h
 *
 *    Description:  Header file for the preprocessor
 *
 *        Version:  1.0
 *        Created:  30/07/2010 15:47:12
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BlackLight (http://0x00.ath.cx), <blacklight@autistici.org>
 *        Licence:  GNU GPL v.3
 *        Company:  DO WHAT YOU WANT CAUSE A PIRATE IS FREE, YOU ARE A PIRATE!
 *
 * =====================================================================================
 */

#ifndef _SPP_AI_H
#define _SPP_AI_H

#include 	"sf_snort_packet.h"
#include 	"sf_dynamic_preprocessor.h"
#include	"uthash.h"

#define 	PRIVATE 		static

extern DynamicPreprocessorData _dpd;
typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;

typedef enum { false, true } BOOL;

typedef enum {
	none, src_port, dst_port, src_addr, dst_addr, timestamp
} cluster_type;

/* Each stream in the hash table is identified by the couple (src_ip, dst_port) */
struct pkt_key
{
	uint32_t src_ip;
	uint16_t dst_port;
};

/* Identifier of a packet in a stream */
struct pkt_info
{
	struct pkt_key    key; 	           /* Key of the packet (src_ip, dst_port) */
	time_t            timestamp;        /* Timestamp */
	SFSnortPacket*    pkt; 	           /* Reference to SFSnortPacket containing packet's information */
	struct pkt_info*  next; 	           /* Pointer to the next packet in the stream */
	BOOL              observed;         /* Flag set if the packet is observed, i.e. associated to a security alert */
	UT_hash_handle    hh; 		      /* Make the struct 'hashable' */
};

/* Data type containing the configuration of the module */
typedef struct
{
	unsigned long hashCleanupInterval;
	unsigned long streamExpireInterval;
	unsigned long alertClusteringInterval;
	char          alertfile[1024];
	char          clusterfile[1024];
} AI_config;

/* Data type for hierarchies used for clustering */
typedef struct _hierarchy_node
{
	cluster_type            type;
	char                    label[256];
	int                     min_val;
	int                     max_val;
	int                     nchildren;
	struct _hierarchy_node  *parent;
	struct _hierarchy_node  **children;
} hierarchy_node;

/* Data type for Snort alerts */
typedef struct _AI_snort_alert  {
	/* Identifiers of the alert */
	unsigned int    gid;
	unsigned int    sid;
	unsigned int    rev;

	/* Snort priority, description,
	 * classification and timestamp
	 * of the alert */
	unsigned short  priority;
	char            *desc;
	char            *classification;
	time_t          timestamp;

	/* IP header information */
	uint8_t         tos;
	uint16_t        iplen;
	uint16_t        id;
	uint8_t         ttl;
	uint8_t         ipproto;
	uint32_t        src_addr;
	uint32_t        dst_addr;

	/* TCP header information */
	uint16_t        src_port;
	uint16_t        dst_port;
	uint32_t        sequence;
	uint32_t        ack;
	uint8_t         tcp_flags;
	uint16_t        window;
	uint16_t        tcplen;

	/* Reference to the TCP stream
	 * associated to the alert, if any */
	struct pkt_info *stream;

	/* Pointer to the next alert in
	 * the log, if any*/
	struct _AI_snort_alert *next;

	/* Hierarchies for addresses and ports,
	 * if the clustering algorithm is used */
	hierarchy_node  *src_addr_node;
	hierarchy_node  *dst_addr_node;
	hierarchy_node  *src_port_node;
	hierarchy_node  *dst_port_node;

	/* If the clustering algorithm is used,
	 * we also count how many alerts this
	 * single alert groups */
	unsigned int    grouped_alarms_count;
} AI_snort_alert;

int                preg_match ( const char*, char*, char***, int* );

void*              AI_hashcleanup_thread ( void* );
void*              AI_alertparser_thread ( void* );

void               AI_pkt_enqueue ( SFSnortPacket* );
void               AI_set_stream_observed ( struct pkt_key key );
void               AI_hierarchies_build ( AI_config*, hierarchy_node**, int );
struct pkt_info*   AI_get_stream_by_key ( struct pkt_key );
AI_snort_alert*    AI_get_alerts ( void );

#endif  /* _SPP_AI_H */

