#!/usr/bin/perl

use strict;
use warnings;
use MIME::Base64;
use Env qw(QUERY_STRING DOCUMENT_ROOT);

sub url_decode  {
	my $str = shift;
	$str =~ s/%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;;
	return $str;
}

sub print_pcap_header  {
	my $out = shift;

	# pcap magic_number
	print $out pack ( 'L', 0xa1b2c3d4 );

	# pcap version_major
	print $out pack ( 'S', 0x2 );

	# pcap version_minor
	print $out pack ( 'S', 0x4 );

	# pcap thiszone
	print $out pack ( 'l', 0x0 );

	# pcap sigfigs
	print $out pack ( 'L', 0x0 );

	# pcap snaplen
	print $out pack ( 'L', 0xffff );

	# pcap network
	print $out pack ( 'L', 0x1 );
}

sub print_packet  {
	my ( $out, $packet ) = @_;

	# ts_sec
	print $out pack ( 'L', $packet->{'time'} );

	# ts_usec
	print $out pack ( 'L', 0x0 );

	my $pkt_data = decode_base64 ( url_decode ( $packet->{'content'} ));
	my $hex = unpack ( 'H*', $pkt_data );
	my @pairs = $hex =~ /([a-fA-F0-9]{2})/g;

	# If this is not an IP packet, trust what the client has told you as packet length
	if (( $pairs[0] ne '45' && $pairs[1] ne '00' ) || ( @pairs < 5 ))
	{
		# incl_len
		print $out pack ( 'L', $packet->{'length'} + 12 );

		# orig_len
		print $out pack ( 'L', $packet->{'length'} + 12 );
	} else {
		# Otherwise, the length of the packet is the one specified in the IP header
		my $length = hex ( $pairs[2].$pairs[3] );

		# If the lengths differ (IP length and actual length of the stream received), pad
		# the end of the packet with some 0's so that its length matches the one
		# specified in the IP header
		if ( $length > ( length ( $hex ) / 2 ))
		{
			my $pad_size = $length - ( length ( $hex ) / 2 );
			$hex .= '00' for ( 0..$pad_size-1 );
			$pkt_data = pack ( 'H*', $hex );
		}

		# Add the length of a pseudo-ethernet header
		$length += 14;

		# incl_len
		print $out pack ( 'L', $length );

		# orig_len
		print $out pack ( 'L', $length );
	}

	# pseudo ethernet header
	print $out pack ( 'H*', 0 x24 );

	# ethernet type (IP)
	print $out pack ( 'S', 0x8 );

	# packet content
	print $out $pkt_data;
}

$QUERY_STRING =~ /packets=([0-9]+)/;
my $packets_num = $1;
my %packets = ();

for ( my $i=0; $i < $packets_num; $i++ )
{
	$QUERY_STRING =~ /packet_len$i=([0-9]+)/;
	my $length = $1;

	$QUERY_STRING =~ /time$i=([0-9]+)/;
	my $time = $1;
	
	$QUERY_STRING =~ /packet$i=(.+?)(&|$)/;
	my $content = $1;

	$packets{$i} = {
		'length'  => $length,
		'time'    => $time,
		'content' => $content
	};
}

print "Content-Type: application/pcap\n\n";

# open my $out, "> $DOCUMENT_ROOT/out.pcap";
open my $out, ">&STDOUT";
binmode $out;
print_pcap_header $out;

for ( my $i=0; $i < $packets_num; $i++ )
{
	print_packet $out, $packets{$i};
}

close $out;

# print "Content-Type: text/html\\n\\n";
# print "<meta http-equiv=\\"refresh\\" content=\\"0;url=/out.pcap\\">\\n";

