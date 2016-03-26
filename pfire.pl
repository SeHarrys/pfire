#!/usr/bin/env perl

=doc
    pFire - Iptables Firewall
=cut

use strict;

use PFire;
use Getopt::Long qw(GetOptions);
use feature qw(say);
use Data::Dumper;

my $Opt = {
    ip        => { arg => 'IP' , extra => 's' },
    port      => { arg => 'Port', extra => 's' },
    dst_ip    => { arg => 'Destionation IP' },
    src_ip    => { arg => 'Source IP' },
    proto     => { arg => 'Protocol' },
    netstat   => { arg => 'Netstat' },
    report    => { arg => 'pFire Report' },
    config    => { arg => 'Config file' , extra => 's' },
    block     => { arg => 'Block Action - proto - ip - port' },
    block_tor => { arg => 'Block TOR' },
    block_country => { arg => 'Block Country ISO format' },
};

sub Uso {
    say qq{\nAvailable options\n};
    map {
	my $pad = length($_) > 9 ? "\t" : "\t\t"; $pad = "\t\t\t" if length($_) < 5;
	say qq{ --$_$pad$Opt->{$_}->{arg}} 
    } sort keys %{$Opt};
    say "";
    exit;
}

GetOptions(
    'test'      => \$Opt->{test}->{val},
    'config=s'  => \$Opt->{config}->{val},
    'netstat'   => \$Opt->{netstat}->{val},
    'report'    => \$Opt->{report}->{val},
    'ip=s'      => \$Opt->{ip}->{val},
    'port=s'    => \$Opt->{port}->{val},
    'dst_ip=s'  => \$Opt->{dst_ip}->{val},
    'src_ip=s'  => \$Opt->{src_ip}->{val},
    'dst_pt=s'  => \$Opt->{dst_pt}->{val},
    'src_pt=s'  => \$Opt->{src_pt}->{val},   
    'proto=s'   => \$Opt->{proto}->{val},
    'block_tor' => \$Opt->{block_tor}->{val},
    'block_country' => \$Opt->{block_country}->{val},
    ) or die Uso($Opt);

my $PFire = new PFire;

## Config and exit
if ( $Opt->{config}->{val} ) {
    if ( -e $Opt->{config}->{val} ) {
	$PFire->LoadConf($Opt->{config}->{val});
    } elsif ( $ENV{'PFIRE'} ) {
	$PFire->LoadConf($ENV{'PFIRE'});
    }
    $PFire->Init();
    $PFire->Report();
    exit;
}
