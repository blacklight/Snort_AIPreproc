#!/usr/bin/env perl

use Env qw(DOCUMENT_ROOT QUERY_STRING);
use strict;
use warnings;

my $method = 'xml';

if ( $QUERY_STRING )
{
	if ( $QUERY_STRING =~ /method=([a-z]+)/ )
	{
		if ( $1 eq 'json' or $1 eq 'xml' )
		{
			$method = $1;
		}
	}
}

my %mon2num = qw( jan 1 feb 2 mar 3 apr 4 may 5 jun 6 jul 7 aug 8 sep 9 oct 10 nov 11 dec 12 );
my $json_file = (( $DOCUMENT_ROOT ) ? $DOCUMENT_ROOT : '.' ).'/correlation_graph.json';
my $json_string = '';

open IN, $json_file or die "Alert JSON file not found";
$json_string .= $_ while ( <IN> );
close IN;

if ( $method eq 'json' )
{
	print "Content-Type: application/json\n\n";
	print $json_string;
} elsif ( $method eq 'xml' ) {
	use JSON;
	use Time::Local;

	my @json =  @{JSON->new->utf8->decode ( $json_string )};
	print "Content-Type: application/xml\n\n".
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\n".
		"<alerts>\n";

	for ( @json )
	{
		print "\t<alert";
		my %element = %$_;

		for my $key ( keys %element )
		{
			if ( $key !~ /[^a-zA-Z0-9_]/ and !UNIVERSAL::isa ( $element{$key}, "ARRAY" ) and !UNIVERSAL::isa ( $element{$key}, "HASH" ))
			{
				my $k = $key;

				if ( $key eq 'snortSID' or $key eq 'snortGID' or $key eq 'snortREV' )
				{
					$k =~ s/^snort//;
					$k = lc $k;
				} elsif ( $key eq 'to' or $key eq 'from' ) {
					if ( $element{$key} =~ /:([1-9][0-9]*)$/ )
					{
						my $port = $1;
						$element{$key} =~ s/^(.*):[1-9][0-9]*$/$1/;
						print " ${key}_port=\"$port\"";
					}
				} elsif ( $key eq 'date' ) {
					if ( $element{$key} =~ /^\s*[a-z]+\s+([a-z]+)\s+([0-9]+)\s+([0-9]+):([0-9]+):([0-9]+)\s+([0-9]+)\s*$/i )
					{
						my $mon  = $mon2num{ lc substr ( $1, 0, 3 )} - 1;
						my $day  = $2;
						my $hour = $3;
						my $min  = $4;
						my $sec  = $5;
						my $year = $6;
						$element{$key} = timelocal ( $sec, $min, $hour, $day, $mon, $year );
					}
				}

				$element{$key} =~ s/(^|[^\\])"/$1\\"/g;
				print " $k=\"".$element{$key}."\"";
			}
		}

		print "></alert>\n";
	}

	print "</alerts>\n";
}

