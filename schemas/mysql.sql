DROP TABLE IF EXISTS ca_ipv4_headers;
CREATE TABLE ca_ipv4_headers (
	ip_hdr_id     integer     auto_increment,
	ip_tos        integer,
	ip_len        integer,
	ip_id         integer,
	ip_ttl        integer,
	ip_proto      integer,
	ip_src_addr   varchar(32),
	ip_dst_addr   varchar(32),

	primary key(ip_hdr_id)
);

DROP TABLE IF EXISTS ca_tcp_headers;
CREATE TABLE ca_tcp_headers (
	tcp_hdr_id     integer    auto_increment,
	tcp_src_port   integer,
	tcp_dst_port   integer,
	tcp_seq        integer,
	tcp_ack        integer,
	tcp_flags      integer,
	tcp_window     integer,
	tcp_len        integer,

	primary key(tcp_hdr_id)
);

DROP TABLE IF EXISTS ca_clustered_alerts;
CREATE TABLE ca_clustered_alerts (
	cluster_id        integer      auto_increment,
	clustered_srcip   varchar(255) default null,
	clustered_dstip   varchar(255) default null,
	clustered_srcport varchar(255) default null,
	clustered_dstport varchar(255) default null,

	primary key(cluster_id)
);

DROP TABLE IF EXISTS ca_alerts;
CREATE TABLE ca_alerts (
	alert_id       integer     auto_increment,
	gid            integer,
	sid            integer,
	rev            integer,
	priority       integer,
	description    varchar(255),
	classification varchar(255),
	timestamp      datetime,
	ip_hdr         integer default 0,
	tcp_hdr        integer default 0,
	cluster_id     integer default 0,

	primary key(alert_id),
	foreign key(ip_hdr) references ca_ip_headers(ip_hdr_id),
	foreign key(tcp_hdr) references ca_tcp_headers(tcp_hdr_id),
	foreign key(cluster_id) references ca_clustered_alerts(cluster_id)
);

DROP TABLE IF EXISTS ca_packet_streams;
CREATE TABLE ca_packet_streams (
	pkt_id         integer     auto_increment,
	alert_id       integer,
	pkt_len        integer,
	timestamp      datetime,
	content        longblob,

	primary key(pkt_id),
	foreign key(alert_id) references ca_alerts(alert_id)
);

DROP TABLE IF EXISTS ca_correlated_alerts;
CREATE TABLE ca_correlated_alerts (
	alert1            integer,
	alert2            integer,
	correlation_coeff double,

	primary key(alert1, alert2),
	foreign key(alert1) references ca_alerts(alert_id),
	foreign key(alert2) references ca_alerts(alert_id)
);

