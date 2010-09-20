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

#ifdef 	HAVE_CONFIG_H
#include	"config.h"
#endif

#include 	"sf_snort_packet.h"
#include 	"sf_dynamic_preprocessor.h"
#include	"uthash.h"

#define 	PRIVATE 		static

/** Default interval in seconds for the thread cleaning up TCP streams */
#define 	DEFAULT_HASH_CLEANUP_INTERVAL 		300

/** Default interval in seconds before a stream without any packet is considered timed out */
#define 	DEFAULT_STREAM_EXPIRE_INTERVAL 		300

/** Default interval in seconds for reading alerts from the alert database, if used */
#define 	DEFAULT_DATABASE_INTERVAL 			30

/** Default interval in seconds for the thread clustering alerts */
#define 	DEFAULT_ALERT_CLUSTERING_INTERVAL 		300

/** Default interval in seconds for running the graph correlation thread */
#define 	DEFAULT_ALERT_CORRELATION_INTERVAL 	300

/** Default path to Snort's log file */
#define 	DEFAULT_ALERT_LOG_FILE 				"/var/log/snort/alert"

/** Default path to Snort's clustered alerts file */
#define 	DEFAULT_CLUSTER_LOG_FILE 			"/var/log/snort/clustered_alerts"

/** Default path to alert correlation rules directory */
#define 	DEFAULT_CORR_RULES_DIR 				"/etc/snort/corr_rules"

/** Default directory for placing correlated alerts information (.dot and possibly .png files) */
#define 	DEFAULT_CORR_ALERTS_DIR 				"/var/log/snort/correlated_alerts"

/** Default path to alert history binary file, used for bayesian statistical correlation over alerts */
#define 	DEFAULT_ALERT_HISTORY_FILE 			"/var/log/snort/alert_history"

/** Default correlation threshold coefficient for correlating two hyperalerts */
#define 	DEFAULT_CORR_THRESHOLD 				0.5

/****************************/
/* Database support */
#ifdef 	HAVE_LIBMYSQLCLIENT
#define 	HAVE_DB 	1
#endif

#ifdef 	HAVE_LIBPQ
#define 	HAVE_DB 	1
#endif
/****************************/

extern DynamicPreprocessorData _dpd;
typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;

typedef enum { false, true } BOOL;

/*****************************************************************/
/** Possible types of clustering attributes */
typedef enum {
	none, src_addr, dst_addr, src_port, dst_port, CLUSTER_TYPES
} cluster_type;
/*****************************************************************/
/** Each stream in the hash table is identified by the couple (src_ip, dst_port) */
struct pkt_key
{
	uint32_t src_ip;
	uint16_t dst_port;
};
/*****************************************************************/
/** Identifier of a packet in a stream */
struct pkt_info
{
	/** Key of the packet (src_ip, dst_port) */
	struct pkt_key    key;

	/** Timestamp */
	time_t            timestamp;

	/** Reference to SFSnortPacket containing packet's information */
	SFSnortPacket*    pkt;

	/** Pointer to the next packet in the stream */
	struct pkt_info*  next;

	/** Flag set if the packet is observed, i.e. associated to a security alert */
	BOOL              observed;

	/** Make the struct 'hashable' */
	UT_hash_handle    hh;
};
/*****************************************************************/
/* Data type containing the configuration of the module */
typedef struct
{
	/** Interval in seconds for the stream cleanup thread */
	unsigned long hashCleanupInterval;

	/** Interval in seconds for considering an idle stream timed out */
	unsigned long streamExpireInterval;

	/** Interval in seconds for the alert clustering thread */
	unsigned long alertClusteringInterval;

	/** Interval in seconds for reading the alert database, if database logging is used */
	unsigned long databaseParsingInterval;

	/** Interval in seconds for running the thread for building alert correlation graphs */
	unsigned long correlationGraphInterval;

	/** Correlation threshold coefficient for correlating two hyperalerts. Two hyperalerts
	 * are 'correlated' to each other in a multi-step attack graph if and only if their
	 * correlation value is >= m + ks, where m is the average correlation coefficient,
	 * s is the standard deviation over this coefficient, and k is this threshold
	 * coefficient. Its value can be >= 0. A value in [0,1] is strongly suggested,
	 * but this value mostly depends on how accurate the correlation rules where
	 * defined. Be careful, defining a correlation coefficient > or >> 1 no correlation
	 * may occur at all! */
	double        correlationThresholdCoefficient;

	/** Alert file */
	char          alertfile[1024];

	/** Alert history binary file */
	char          alert_history_file[1024];

	/** Clustered alerts file */
	char          clusterfile[1024];

	/** Correlation rules path */
	char          corr_rules_dir[1024];

	/** Directory where the correlated alerts' information will be placed */
	char          corr_alerts_dir[1024];

	/** Database name, if database logging is used */
	char          dbname[256];

	/** Database user, if database logging is used */
	char          dbuser[256];

	/** Database password, if database logging is used */
	char          dbpass[256];

	/** Database host, if database logging is used */
	char          dbhost[256];
} AI_config;
/*****************************************************************/
/** Data type for hierarchies used for clustering */
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
/*****************************************************************/
/** Key for the hyperalert hash table */
typedef struct
{
	unsigned int gid;
	unsigned int sid;
	unsigned int rev;
} AI_hyperalert_key;
/*****************************************************************/
/** Hyperalert hash table */
typedef struct
{
	/** Hyperalert key */
	AI_hyperalert_key  key;

	/** Pre-conditions, as array of strings */
	char               **preconds;

	/** Number of pre-conditions */
	unsigned int       n_preconds;

	/** Post-conditions, as array of strings */
	char               **postconds;

	/** Number of post-conditions */
	unsigned int       n_postconds;

	/** Make the struct 'hashable' */
	UT_hash_handle     hh;
} AI_hyperalert_info;
/*****************************************************************/
/** Data type for Snort alerts */
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
	uint8_t         ip_tos;
	uint16_t        ip_len;
	uint16_t        ip_id;
	uint8_t         ip_ttl;
	uint8_t         ip_proto;
	uint32_t        ip_src_addr;
	uint32_t        ip_dst_addr;

	/* TCP header information */
	uint16_t        tcp_src_port;
	uint16_t        tcp_dst_port;
	uint32_t        tcp_seq;
	uint32_t        tcp_ack;
	uint8_t         tcp_flags;
	uint16_t        tcp_window;
	uint16_t        tcp_len;

	/** Reference to the TCP stream
	 * associated to the alert, if any */
	struct pkt_info *stream;

	/** Pointer to the next alert in
	 * the log, if any*/
	struct _AI_snort_alert *next;

	/** Hierarchies for addresses and ports,
	 * if the clustering algorithm is used */
	hierarchy_node  *h_node[CLUSTER_TYPES];

	/** If the clustering algorithm is used,
	 * keep tracked of the pointers to the
	 * single grouped alerts */
	struct _AI_snort_alert **grouped_alerts;

	/** If the clustering algorithm is used,
	 * we also count how many alerts this
	 * single alert groups */
	unsigned int    grouped_alerts_count;

	/** Hyperalert information, pre-conditions
	 * and post-conditions*/
	AI_hyperalert_info  *hyperalert;

	/* Parent alerts in the chain, if any */
	struct _AI_snort_alert  **parent_alerts;

	/* Number of parent alerts */
	unsigned int        n_parent_alerts;

	/** Array of directly correlated 'derived'
	 * alerts from the current one, if any */
	struct _AI_snort_alert  **derived_alerts;

	/** Number of derived alerts */
	unsigned int        n_derived_alerts;
} AI_snort_alert;
/*****************************************************************/

int                preg_match ( const char*, char*, char***, int* );
char*              str_replace ( char *str, char *orig, char *rep );
char*              str_replace_all ( char *str, char *orig, char *rep );

void*              AI_hashcleanup_thread ( void* );
void*              AI_file_alertparser_thread ( void* );
void*              AI_alert_correlation_thread ( void* );

#ifdef 	HAVE_DB
AI_snort_alert*    AI_db_get_alerts ( void );
void               AI_db_free_alerts ( AI_snort_alert *node );
void*              AI_db_alertparser_thread ( void* );
#endif

void               AI_pkt_enqueue ( SFSnortPacket* );
void               AI_set_stream_observed ( struct pkt_key key );
void               AI_hierarchies_build ( AI_config*, hierarchy_node**, int );
void               AI_free_alerts ( AI_snort_alert *node );

struct pkt_info*   AI_get_stream_by_key ( struct pkt_key );
AI_snort_alert*    AI_get_alerts ( void );
AI_snort_alert*    AI_get_clustered_alerts ( void );

void               AI_serialize_alert ( AI_snort_alert*, AI_config* );
void               AI_deserialize_alert ( AI_snort_alert*, AI_config* );

/** Function pointer to the function used for getting the alert list (from log file, db, ...) */
extern AI_snort_alert* (*get_alerts)(void);

#endif  /* _SPP_AI_H */

