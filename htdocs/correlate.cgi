#!/usr/bin/env perl

use strict;
use warnings;
use XML::Simple;
use Data::Dumper;
use Env qw(QUERY_STRING DOCUMENT_ROOT);

exit 1 if ( !$QUERY_STRING );

$QUERY_STRING =~ /action=([a-z]+)/;
my $action = $1;

$QUERY_STRING =~ /from_sid=([0-9]+)/;
my $from_sid = $1;

$QUERY_STRING =~ /from_gid=([0-9]+)/;
my $from_gid = $1;

$QUERY_STRING =~ /from_rev=([0-9]+)/;
my $from_rev = $1;

$QUERY_STRING =~ /to_sid=([0-9]+)/;
my $to_sid = $1;

$QUERY_STRING =~ /to_gid=([0-9]+)/;
my $to_gid = $1;

$QUERY_STRING =~ /to_rev=([0-9]+)/;
my $to_rev = $1;

exit 1 unless (
		defined ( $action ) &&
		defined ( $from_sid ) &&
		defined ( $from_gid ) &&
		defined ( $from_rev ) &&
		defined ( $to_sid ) &&
		defined ( $to_gid ) &&
		defined ( $to_rev ));

my $xml  = new XML::Simple ( forcearray => 1 );
my $corr_data = $xml->XMLin ( "$DOCUMENT_ROOT/manual_correlations.xml" );
my $uncorr_data = $xml->XMLin ( "$DOCUMENT_ROOT/manual_uncorrelations.xml" );

if ( $action eq 'add' )
{
	# Check if 'correlation' already contains this item
	for my $node ( @{$corr_data->{'correlation'}} )
	{
		my $from = @{$node->{'from'}}[0];
		my $to   = @{$node->{'to'}}[0];

		exit 1 if (
			$from->{'sid'} eq $from_sid &&
			$from->{'gid'} eq $from_gid &&
			$from->{'rev'} eq $from_rev &&
			$to->{'sid'}   eq $to_sid   &&
			$to->{'gid'}   eq $to_gid   &&
			$to->{'rev'}   eq $to_rev
		);
	}

	# If this node is in 'uncorrelated' alerts, remove it from there
	if ( UNIVERSAL::isa ( $uncorr_data->{'correlation'}, "ARRAY" ))
	{
		for my $i ( 0..@{$uncorr_data->{'correlation'}}-1 )
		{
			if ( defined ( @{$uncorr_data->{'correlation'}}[$i] ))
			{
				my $from = @{@{$uncorr_data->{'correlation'}}[$i]->{'from'}}[0];
				my $to   = @{@{$uncorr_data->{'correlation'}}[$i]->{'to'}}[0];

				splice ( @{$uncorr_data->{'correlation'}}, $i, 1 ) if (
					$from->{'sid'} eq $from_sid &&
					$from->{'gid'} eq $from_gid &&
					$from->{'rev'} eq $from_rev &&
					$to->{'sid'}   eq $to_sid   &&
					$to->{'gid'}   eq $to_gid   &&
					$to->{'rev'}   eq $to_rev
				);
			}
		}
	}

	my %hash = (
		'to' => [
		{
			'sid' => $to_sid,
			'gid' => $to_gid,
			'rev' => $to_rev,
		}
		],
			'from' => [
			{
				'sid' => $from_sid,
				'gid' => $from_gid,
				'rev' => $from_rev
			}
		]
	);

	push @{$corr_data->{'correlation'}}, \%hash;
} elsif ( $action eq 'remove' ) {
	# Check if 'un-correlation' already contains this item
	for my $node ( @{$uncorr_data->{'correlation'}} )
	{
		my $from = @{$node->{'from'}}[0];
		my $to   = @{$node->{'to'}}[0];

		exit 1 if (
			$from->{'sid'} eq $from_sid &&
			$from->{'gid'} eq $from_gid &&
			$from->{'rev'} eq $from_rev &&
			$to->{'sid'}   eq $to_sid   &&
			$to->{'gid'}   eq $to_gid   &&
			$to->{'rev'}   eq $to_rev
		);
	}

	# If this node is in 'correlated' alerts, remove it from there
	if ( UNIVERSAL::isa ( $corr_data->{'correlation'}, "ARRAY" ))
	{
		for my $i ( 0..@{$corr_data->{'correlation'}}-1 )
		{
			if ( defined ( @{$corr_data->{'correlation'}}[$i] ))
			{
				my $from = @{@{$corr_data->{'correlation'}}[$i]->{'from'}}[0];
				my $to   = @{@{$corr_data->{'correlation'}}[$i]->{'to'}}[0];

				splice ( @{$corr_data->{'correlation'}}, $i, 1 ) if (
					$from->{'sid'} eq $from_sid &&
					$from->{'gid'} eq $from_gid &&
					$from->{'rev'} eq $from_rev &&
					$to->{'sid'}   eq $to_sid   &&
					$to->{'gid'}   eq $to_gid   &&
					$to->{'rev'}   eq $to_rev
				);
			}
		}
	}

	my %hash = (
		'to' => [
		{
			'sid' => $to_sid,
			'gid' => $to_gid,
			'rev' => $to_rev
		}
		],
			'from' => [
			{
				'sid' => $from_sid,
				'gid' => $from_gid,
				'rev' => $from_rev
			}
		]
	);

	push @{$uncorr_data->{'correlation'}}, \%hash;
}

my $xml_corr_out = $xml->XMLout ( $corr_data, RootName => "correlations" );
my $xml_uncorr_out = $xml->XMLout ( $uncorr_data, RootName => "correlations" );

open  OUT, "> $DOCUMENT_ROOT/manual_correlations.xml" or exit 1;
print OUT "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
print OUT "<!DOCTYPE hyperalert PUBLIC \"-//blacklight//DTD MANUAL CORRELATIONS//EN\" \"http://0x00.ath.cx/manual_correlations.dtd\">\n\n";
print OUT $xml_corr_out."\n";
close OUT;

open  OUT, "> $DOCUMENT_ROOT/manual_uncorrelations.xml" or exit 1;
print OUT "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
print OUT "<!DOCTYPE hyperalert PUBLIC \"-//blacklight//DTD MANUAL CORRELATIONS//EN\" \"http://0x00.ath.cx/manual_correlations.dtd\">\n\n";
print OUT $xml_uncorr_out."\n";
close OUT;

print "Content-Type: text/html\n\n";

