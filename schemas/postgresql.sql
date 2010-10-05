DROP TABLE IF EXISTS ca_ipv4_headers CASCADE;
CREATE TABLE ca_ipv4_headers (
	ip_hdr_id     serial   primary key,
	ip_tos        integer,
	ip_len        integer,
	ip_id         integer,
	ip_ttl        integer,
	ip_proto      integer,
	ip_src_addr   varchar(32),
	ip_dst_addr   varchar(32)
);
INSERT INTO ca_ipv4_headers ( ip_hdr_id ) VALUES ( 0 );

DROP TABLE IF EXISTS ca_tcp_headers CASCADE;
CREATE TABLE ca_tcp_headers (
	tcp_hdr_id     serial   primary key,
	tcp_src_port   integer,
	tcp_dst_port   integer,
	tcp_seq        bigint,
	tcp_ack        bigint,
	tcp_flags      integer,
	tcp_window     integer,
	tcp_len        integer
);
INSERT INTO ca_tcp_headers ( tcp_hdr_id ) VALUES ( 0 );

DROP TABLE IF EXISTS ca_clustered_alerts CASCADE;
CREATE TABLE ca_clustered_alerts (
	cluster_id        serial   primary key,
	clustered_srcip   varchar(255) default null,
	clustered_dstip   varchar(255) default null,
	clustered_srcport varchar(255) default null,
	clustered_dstport varchar(255) default null
);
INSERT INTO ca_clustered_alerts ( cluster_id ) VALUES ( 0 );

DROP TABLE IF EXISTS ca_alerts CASCADE;
CREATE TABLE ca_alerts (
	alert_id       serial    primary key,
	gid            integer,
	sid            integer,
	rev            integer,
	priority       integer,
	description    varchar(255),
	classification varchar(255),
	timestamp      timestamp,
	ip_hdr         integer default 0 references ca_ipv4_headers(ip_hdr_id),
	tcp_hdr        integer default 0 references ca_tcp_headers(tcp_hdr_id),
	cluster_id     integer default 0 references ca_clustered_alerts(cluster_id)
);

DROP TABLE IF EXISTS ca_packet_streams CASCADE;
CREATE TABLE ca_packet_streams (
	pkt_id         serial   primary key,
	alert_id       integer  references ca_alerts(alert_id),
	pkt_len        integer,
	timestamp      timestamp,
	content        bytea
);

DROP TABLE IF EXISTS ca_correlated_alerts CASCADE;
CREATE TABLE ca_correlated_alerts (
	alert1            integer   references ca_alerts(alert_id),
	alert2            integer   references ca_alerts(alert_id),
	correlation_coeff real,

	primary key(alert1, alert2)
);

