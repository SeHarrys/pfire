#!/usr/bin/env perl

use strict;

use HTTP::Tiny;
use Data::Dumper;
use JSON qw(decode_json);
use feature qw(say);

my $version = 001;

my ($conf,$sys,$net);

sub Netstat {
    my @a = qx(netstat -lntu);

    shift @a for 1 .. 2;

    for (@a) {
       chomp;
       my @v = split ' ',$_;
       my ($ip,$port) = split ':',$v[3];
       $net->{listen}->{$v[0]}->{$ip} = $port if $ip =~ /^\d/;
    }
}

sub LoadConf {
    my $f = shift;
    my $t;

    if ( $f =~ /^http/ ) {
	$t = HTTP::Tiny->new->get($f)->{content};
    } else {
	local $/;
	open( my $fh, '<', $f );
	$t = <$fh>;
	close($fh);
    }

    return decode_json( $t );
}

sub Block_TOR {
    my $TOR_List = 'https://www.dan.me.uk/torlist/';

    my $t = HTTP::Tiny->new->get($TOR_List)->{content};

    X('-N block-tor');
    X('-A block-tor -j DROP');

    for my $IP ( split '\n',$t ) {
	X("-A INPUT -s $IP -j block-tor");
    }

}

sub Block_Country {
    my $country = shift;

    my $url = 'http://www.ipdeny.com/ipblocks/data/countries/'.$country.'.zone';

    my $chain = "block-country-$country";

    X("-N $chain");
    X("-A $chain -j DROP");

    my $t = HTTP::Tiny->new->get($url)->{content};

    for my $IP ( split '\n',$t ) {
	X("-A INPUT -s $IP -j $chain");
    }

}

sub ReadIF {
    my $t;

    ## Linux::net::dev
    my (@titles,%result);
    open( my $fh, '<', '/proc/net/dev' );
    while(my $line = <$fh>) {
	if ($line =~ /^.{6}\|([^\\]+)\|([^\\]+)$/) {
	    my ($rec, $trans) = ($1, $2);
	    @titles = (
	  (map { "r$_" } split(/\s+/, $rec)),
	  (map { "t$_" } split(/\s+/, $trans)),
	  );
	} elsif ($line =~ /^\s*([^:]+):\s*(.*)$/) {
	    my ($id, @data) = ($1, split(/\s+/, $2));

	    $result{$id} = { map {
		$titles[$_] => $data[$_];
			     } (0..$#titles) };
	}
    }

    close($fh);
    $sys->{dev} = \%result;

    ## Networks IPv6
    local $/;
    open( my $fh, '<', '/proc/net/if_inet6' );
    $t = <$fh>;
    close($fh);

    my @a = split ' ',$t;
    for(1 .. scalar(@a)/6) {
	my $c = ($_*6)-1;
	$sys->{dev}->{$a[$c]}->{ipv6} = 1;
    }

    $conf->{init}->{devs} = { map { $_ => 0 } keys $sys->{dev} };
}

sub X {
    my $a = shift;

    if ( $conf->{action} eq 'save' ) {
	print {$conf->{fd}} $a."\n";
    } else {
	qx(/sbin/iptables $a);
    }

    #say $a;
}

sub Forward {
    my $f = shift;
    X('-t nat -A POSTROUTING -o '.$f->{net_out}.' -j MASQUERADE');
    X('-A FORWARD -i '.$f->{net_in}.' -j ACCEPT');

    ## PPPoE : Clamp MSS to PMTU - http://www.tldp.org/HOWTO/IP-Masquerade-HOWTO/mtu-issues.html
    X('-I FORWARD -p tcp --tcp-flags SYN,RST SYN '.
      '-j TCPMSS --clamp-mss-to-pmtu') if $f->{pppoe};

    ## Transparent Proxy
    X('-t nat -A PREROUTING -i '.$f->{net_in}.
      ' -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128') if $f->{tproxy};
}

sub Chains {
    my @drop = qw(secure block-from blacklist-ip trusted-mac);
    my @drop_log = qw(limit-drop paranoid);

    for my $c (@drop) {
	X("-N ".$c);
	X("-A ".$c." -j DROP");
    }

    for my $c (@drop_log) {
	X("-N ".$c);
	X("-A ".$c." -j ULOG --ulog-prefix '".$c.":'");
	X("-A ".$c." -j DROP");
    }
}

# Redirect( { i => 'eth1' , dport => '1111' , to => '2222' , proto => 'tcp' } );
sub Redirect {
    my $s = shift;

    $s->{p} = 'tcp' unless $s->{p};

    push @{$net->{services}->{$s->{p}}->{$s->{dport}}},
    "[DNAT] Redirect ".uc($s->{p})." ".$s->{i}.":".$s->{dport}." >> ".$s->{to};

    mk_array((
	'-t', 'nat',
	'-A', 'PREROUTING',
	'-i', $s->{i},
	'-p', $s->{p},
	'--dport', $s->{dport},
	'-j', 'DNAT',
	'--to-destination', $s->{to}
	     ));
}

# AcceptSyn : ASyn( { i => 'eth1' , dport => 22 } );
sub ASyn {
    my $s = shift;
    my $chain = shift // 'INPUT';

    mk_array((
	'-I' , $chain,
	'-i' , $s->{i},
	'-p' , 'tcp --syn',
	'--dport' , $s->{dport},
	'-j' , 'ACCEPT'
	     ));
}

# Accept( { i => 'eth1' , dport => 22 , p => 'tcp' } );
sub Accept {
    my $s = shift;
    my $chain = shift // 'INPUT';

    push @{$net->{services}->{$s->{p}}->{$s->{dport}}},
    "[$chain] Accept ".uc($s->{p})." > ".$s->{i}.":".$s->{dport};

    mk_array((
	'-I' , $chain,
	'-i' , $s->{i},
	'-p' , $s->{p},
	'--dport' , $s->{dport},
	'-j' , 'ACCEPT'
	     ));
}

# Block( { i => 'eth1' , p => 'tcp' , dport => 53 } );
sub Block {
    my $s = shift;
    my $chain = shift // 'INPUT';

    push @{$net->{services}->{$s->{p}}->{$s->{dport}}},
    "[$chain] Block ".uc($s->{p})." > ".$s->{i}.":".$s->{dport};

    mk_array((
	'-I' , $chain,
	'-i' , $s->{i},
	'-p' , $s->{p},
	'--dport' , $s->{dport},
	'-j' , 'DROP'
	     ));
}

# BlockIP('9.9.9.9');
sub BlockIP {
    mk_array((
	'-A', 'INPUT',
	'-s' , shift ,
	'-j', 'blacklist-ip'
	     ));
}

sub mk_array {
    my @x = @_;
    my ($s,$t,$c) = ('',1,scalar(@x)/2);

    for (1 .. $c) {
	$s .= $x[$t-1].' '.$x[$t].' ';
	$t += 2;
    }

    X($s);
}

sub ICMP {
    X('-N icmp_in');
    ## ICMP Echo Reply
    X('-A icmp_in -p icmp -m icmp --icmp-type 0 -j ACCEPT');
    ## ICMP Destination Unreachable
    X('-A icmp_in -p icmp -m icmp --icmp-type 3 -j ACCEPT');
    ## ICMP Source Quench
    X('-A icmp_in -p icmp -m icmp --icmp-type 4 -j ACCEPT');
    ## ICMP Echo Request
    X('-A icmp_in -p icmp -m icmp --icmp-type 8 -m recent --set');
    X('-A icmp_in -p icmp -m icmp --icmp-type 8 -m recent --update --seconds 8 --hitcount 10 -j DROP');
    ## ICMP Time Exceeded
    X('-A icmp_in -p icmp -m icmp --icmp-type 11 -j ACCEPT');
    ## ICMP Parameter Problem
    X('-A icmp_in -p icmp -m icmp --icmp-type 12 -j ACCEPT');

    X('-A INPUT -p icmp -j DROP');
}

sub Police {
    my $dev = shift;
    my $j   = shift;

    if ( $j =~ /secure/ ) {
	X('-A INPUT -i '.$dev.' -p tcp --syn -j DROP');
	X('-A INPUT -i '.$dev.' -p udp -j ACCEPT');
    } elsif ( $j =~ /paranoid/ ) {
	$j = 'DROP';
	X('-A INPUT -i '.$dev.' -p tcp --syn -j '.$j);
	X('-A INPUT -i '.$dev.' -p udp -j '.$j);
    } elsif ( $j =~ /intranet/ ) {
	#$j = 'ACCEPT';
	#X('-A INPUT -i '.$dev.' -p tcp -j '.$j);
	#X('-A INPUT -i '.$dev.' -p udp -j '.$j);
    } else {
	$j = 'ACCEPT';
	X('-A INPUT -i '.$dev.' -p tcp -j '.$j);
	X('-A INPUT -i '.$dev.' -p udp -j '.$j);
    }

}

sub Process_Dev {
    my $dev = shift;

    # Disabled
    return unless $dev->{status};

    unless (exists $conf->{init}->{devs}->{$dev->{dev}} ) {
	say "Network not found:".$dev->{dev};
	exit;
    }

    ## Process
    $conf->{init}->{devs}->{$dev->{dev}} = 1;

    # Next if Neutral
    return if $dev->{police} eq 'neutral';

    Police($dev->{dev},$dev->{police});

    ## Block Country
    map { Block_Country($_) } @{$dev->{block_country}} if $dev->{block_country};

    if ( $dev->{police} eq 'secure' ) {
	Accept( { i => $dev->{dev}, dport => $_ , p => 'tcp' } ) for @{$dev->{services}->{tcp}};
	Block( { i => $dev->{dev}, dport => $_ , p => 'udp' } ) for @{$dev->{services}->{udp}};
    } elsif ( $dev->{police} eq 'paranoid' ) {
	ASyn( { i => $dev->{dev}, dport => $_ }) for @{$dev->{services}->{tcp}};
	Accept( { i => $dev->{dev}, dport => $_  , p => 'udp' }) for @{$dev->{services}->{udp}};
    } elsif ( $dev->{police} eq 'open' ) {
	Block( { i => $dev->{dev} , p => 'tcp' , dport => $_ } ) for @{$dev->{services}->{tcp}};
	Block( { i => $dev->{dev} , p => 'udp' , dport => $_ } ) for @{$dev->{services}->{udp}};
    }

    if ( $dev->{trusted_macs} ) {
	X('-I INPUT -p tcp -m mac --mac-source '.$_.' -j trusted-mac') for @{$dev->{trusted_macs}};
    }

    if ( $dev->{services}->{limits} ) {
	for my $port (keys $dev->{services}->{limits} ) {
	    X('-I INPUT -p tcp --dport '.$port.' -i '.$dev->{dev}.' -m state --state NEW -m recent --update '.$dev->{services}->{limits}->{$port}.' --name port'.$port.' -j limit-drop');
	    X('-I INPUT -p tcp --dport '.$port.' -m state --state NEW -m recent --name port'.$port.' --set');
	}
    }

    if ( $dev->{redirect} ) {
	for my $K ( keys $dev->{redirect}->{tcp} ) {
	    Redirect( { i => $dev->{dev} , dport => $K , to => $dev->{redirect}->{tcp}->{$K} });
	}
    }

    if ( $dev->{block_from} ) {
	for my $IP ( keys $dev->{block_from} ) {
	    for my $protocol ( keys $dev->{block_from}->{$IP} ) {
		for my $port ( @{$dev->{block_from}->{$IP}->{$protocol}} ) {
		    X('-A INPUT -p '.$protocol.' -s '.$IP.' --dport '.$port.' -j block-from');
		}
	    }
	}
    }

    if ( $dev->{block_out} ) {
	for my $IP ( keys $dev->{block_out} ) {
	    X('-I FORWARD -s 0/0 -d '.$IP.' -j DROP');
	    X('-I FORWARD -s '.$IP.' -d 0/0 -j DROP');
	}
    }

    if ( $dev->{alias} ) {
	#Process_Dev($dev->{alias}->{$_}) for keys $dev->{alias};
    }

}

sub Init {

    ## Clean
    X('-F');
    X('-X');
    X('-t nat -F');
    X('-t nat -X');
    X('-t mangle -F');
    X('-t mangle -X');

    ## Always lo
    X('-A INPUT -i lo -j ACCEPT');
    $conf->{init}->{devs}->{'lo'} = 1;

    Chains();
    Forward($conf->{forward}) if $conf->{forward}->{enable};
    ICMP() if $conf->{icmp};

    Process_Dev($conf->{devs}->{$_}) for keys $conf->{devs};

    Block_TOR() if $conf->{secure}->{block_tor};

    map { BlockIP($_) } @{$conf->{block_ip}} if $conf->{block_ip};

    ## save rules
    #qx(/sbin/iptables-save > /etc/iptables/rules);
}

sub Report {
    say "Net :";
    for my $Net ( keys $conf->{init}->{devs} ) {
	say $conf->{init}->{devs}->{$Net} ? "\t$Net OK" : "\t$Net No config";
    }

    say "iptables :";
    for my $proto (qw(tcp udp)) {
	next unless $net->{services}->{$proto};
	for my $S ( keys $net->{services}->{$proto} ) {
	    map { say "\t$_" } @{$net->{services}->{$proto}->{$S}};
	}
    }

    say "listen :";
    for my $proto (qw(tcp udp)) {
	next unless $net->{listen}->{$proto};
	say "\t[$proto]\t$_:".$net->{listen}->{$proto}->{$_} for
	    keys $net->{listen}->{$proto};
    }
}

## MAIN

if ( -e '/etc/pfire.conf' ) {
    $conf = LoadConf('/etc/pfire.conf');
} elsif ( $ENV{'PFIRE'} ) {
    $conf = LoadConf($ENV{'PFIRE'});
} elsif ( $ARGV[0] ) {
    $conf = LoadConf($ARGV[0]);
} else {
    say "Need a config file";
    exit;
}

open($conf->{fd},">","iptables-save") if $conf->{action} eq 'save';

Netstat();
ReadIF();
Init();
Report();

close($conf->{fd}) if $conf->{action} eq 'save';
