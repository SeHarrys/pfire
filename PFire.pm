package PFire;

use strict;
use Data::Dumper;

use Moo;
use HTTP::Tiny;
use JSON qw(decode_json);
use feature qw(say);

has conf => ( is => 'rw' );
has fd   => ( is => 'rw' );
has net  => ( is => 'rw' );
has sys  => ( is => 'rw' );

our $VERSION = '0.03';

sub BUILD {
    my ($self,$args) = @_;

}

sub DEMOLISH {
    my ($self, $args) = @_;

    close($self->{fd}) if $self->conf->{action} eq 'save';
}

sub LoadConf {
    my $self = shift;
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

    $self->conf(decode_json( $t ));
}

sub X {
    my $self = shift;
    my $a = shift;
    
    if ( $self->conf->{action} eq 'save' ) {
	print {$self->fd} $a."\n";
    } else {
	qx(/sbin/iptables $a);
    }

    say $a if $ENV{'PFIRE_DEBUG'};
}

sub Init {
    my $self = shift;

    ## Ready structs
    $self->net({});
    $self->sys({});
    
    ## Init vars
    $self->Netstat();
    $self->ReadIF();

    ## Template file
    if ( $self->conf->{action} eq 'save' ) {
	my $save = $self->conf->{template} // 'iptables-save';
	open($self->{fd},">",$save);
    }

    ## Backup
    if ( $self->conf->{backup} ) {
	my $save = 'pfire-backup-'.time();
	qx(/sbin/iptables-save > $save);
    }

    ## Clean
    $self->X('-F');
    $self->X('-X');
    $self->X('-t nat -F');
    $self->X('-t nat -X');
    $self->X('-t mangle -F');
    $self->X('-t mangle -X');

    ## Always lo
    $self->X('-A INPUT -i lo -j ACCEPT');
    $self->conf->{init}->{devs}->{'lo'} = 1;

    $self->Chains();
    $self->Forward($self->conf->{forward}) if $self->conf->{forward}->{enable};
    $self->ICMP() if $self->conf->{icmp};

    $self->Process_Dev($self->conf->{devs}->{$_}) for keys %{ $self->conf->{devs} };

    $self->Block_TOR() if $self->conf->{secure}->{block_tor};

    map { $self->BlockIP($_) } @{$self->conf->{block_ip}} if $self->conf->{block_ip};    
}

sub Chains {
    my $self = shift;
    
    my @drop = qw(secure block-from blacklist-ip trusted-mac fail2ban);
    my @drop_log = qw(limit-drop paranoid);

    for my $c (@drop) {
	$self->X("-N ".$c);
	$self->X("-A ".$c." -j DROP");
    }

    for my $c (@drop_log) {
	$self->X("-N ".$c);
	$self->X("-A ".$c." -j ULOG --ulog-prefix '".$c.":'");
	$self->X("-A ".$c." -j DROP");
    }
}

sub Forward {
    my $self = shift;
    my $f = shift;

    $self->X('-t nat -A POSTROUTING -o '.$f->{net_out}.' -j MASQUERADE');
    $self->X('-A FORWARD -i '.$f->{net_in}.' -j ACCEPT');

    ## PPPoE : Clamp MSS to PMTU - http://www.tldp.org/HOWTO/IP-Masquerade-HOWTO/mtu-issues.html
    $self->X('-I FORWARD -p tcp --tcp-flags SYN,RST SYN '.
	     '-j TCPMSS --clamp-mss-to-pmtu') if $f->{pppoe};

    ## Transparent Proxy
    $self->X('-t nat -A PREROUTING -i '.$f->{net_in}.
	     ' -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128') if $f->{tproxy};
}

sub ICMP {
    my $self = shift;
    
    $self->X('-N icmp_in');
    ## ICMP Echo Reply
    $self->X('-A icmp_in -p icmp -m icmp --icmp-type 0 -j ACCEPT');
    ## ICMP Destination Unreachable
    $self->X('-A icmp_in -p icmp -m icmp --icmp-type 3 -j ACCEPT');
    ## ICMP Source Quench
    $self->X('-A icmp_in -p icmp -m icmp --icmp-type 4 -j ACCEPT');
    ## ICMP Echo Request
    $self->X('-A icmp_in -p icmp -m icmp --icmp-type 8 -m recent --set');
    $self->X('-A icmp_in -p icmp -m icmp --icmp-type 8 -m recent --update --seconds 8 --hitcount 10 -j DROP');
    ## ICMP Time Exceeded
    $self->X('-A icmp_in -p icmp -m icmp --icmp-type 11 -j ACCEPT');
    ## ICMP Parameter Problem
    $self->X('-A icmp_in -p icmp -m icmp --icmp-type 12 -j ACCEPT');

    $self->X('-A INPUT -p icmp -j DROP');
}

sub Process_Dev {
    my $self = shift;
    my $dev = shift;

    # Disabled
    return unless $dev->{status};

    unless (exists $self->conf->{init}->{devs}->{$dev->{dev}} ) {
	say "Network not found:".$dev->{dev};
	exit;
    }

    ## Process
    $self->conf->{init}->{devs}->{$dev->{dev}} = 1;

    # Next if Neutral
    return if $dev->{police} eq 'neutral';

    $self->Police($dev->{dev},$dev->{police});

    ## Block Country
    map { $self->Block_Country($_) } @{$dev->{block_country}} if $dev->{block_country};

    if ( $dev->{police} eq 'secure' ) {
	$self->Accept( { i => $dev->{dev}, dport => $_ , p => 'tcp' } ) for @{$dev->{services}->{tcp}};
	$self->Block( { i => $dev->{dev}, dport => $_ , p => 'udp' } ) for @{$dev->{services}->{udp}};
    } elsif ( $dev->{police} eq 'paranoid' ) {
	$self->ASyn( { i => $dev->{dev}, dport => $_ }) for @{$dev->{services}->{tcp}};
	$self->Accept( { i => $dev->{dev}, dport => $_  , p => 'udp' }) for @{$dev->{services}->{udp}};
    } elsif ( $dev->{police} eq 'open' ) {
	$self->Block( { i => $dev->{dev} , p => 'tcp' , dport => $_ } ) for @{$dev->{services}->{tcp}};
	$self->Block( { i => $dev->{dev} , p => 'udp' , dport => $_ } ) for @{$dev->{services}->{udp}};
    }

    if ( $dev->{trusted_macs} ) {
	$self->X('-I INPUT -p tcp -m mac --mac-source '.$_.' -j trusted-mac') for @{$dev->{trusted_macs}};
    }

    if ( $dev->{services}->{limits} ) {
	for my $port (keys %{ $dev->{services}->{limits} } ) {
	    $self->X('-I INPUT -p tcp --dport '.$port.' -i '.$dev->{dev}.' -m state --state NEW -m recent --update '.$dev->{services}->{limits}->{$port}.' --name port'.$port.' -j limit-drop');
	    $self->X('-I INPUT -p tcp --dport '.$port.' -m state --state NEW -m recent --name port'.$port.' --set');
	}
    }

    if ( $dev->{redirect} ) {
	for my $K ( keys %{ $dev->{redirect}->{tcp} } ) {
	    $self->Redirect( { i => $dev->{dev} , dport => $K , to => $dev->{redirect}->{tcp}->{$K} });
	}
    }

    if ( $dev->{block_from} ) {
	for my $IP ( keys %{ $dev->{block_from} } ) {
	    for my $protocol ( keys %{ $dev->{block_from}->{$IP} } ) {
		for my $port ( @{$dev->{block_from}->{$IP}->{$protocol}} ) {
		    $self->X('-A INPUT -p '.$protocol.' -s '.$IP.' --dport '.$port.' -j block-from');
		}
	    }
	}
    }

    if ( $dev->{block_out} ) {
	for my $IP ( keys %{ $dev->{block_out} } ) {
	    $self->X('-I FORWARD -s 0/0 -d '.$IP.' -j DROP');
	    $self->X('-I FORWARD -s '.$IP.' -d 0/0 -j DROP');
	}
    }

    if ( $dev->{alias} ) {
	#$self->Process_Dev($dev->{alias}->{$_}) for keys $dev->{alias};
    }

}

sub Police {
    my $self = shift;
    my $dev = shift;
    my $j   = shift;

    if ( $j =~ /secure/ ) {
	$self->X('-A INPUT -i '.$dev.' -p tcp --syn -j DROP');
	$self->X('-A INPUT -i '.$dev.' -p udp -j ACCEPT');
    } elsif ( $j =~ /paranoid/ ) {
	$j = 'DROP';
	$self->X('-A INPUT -i '.$dev.' -p tcp --syn -j '.$j);
	$self->X('-A INPUT -i '.$dev.' -p udp -j '.$j);
    } elsif ( $j =~ /intranet/ ) {
	#$j = 'ACCEPT';
	#$self->X('-A INPUT -i '.$dev.' -p tcp -j '.$j);
	#$self->X('-A INPUT -i '.$dev.' -p udp -j '.$j);
    } else {
	$j = 'ACCEPT';
	$self->X('-A INPUT -i '.$dev.' -p tcp -j '.$j);
	$self->X('-A INPUT -i '.$dev.' -p udp -j '.$j);
    }

}

# Redirect( { i => 'eth1' , dport => '1111' , to => '2222' , proto => 'tcp' } );
sub Redirect {
    my $self = shift;
    my $s = shift;

    $s->{p} = 'tcp' unless $s->{p};

    push @{$self->net->{services}->{$s->{p}}->{$s->{dport}}},
    "[DNAT] Redirect ".uc($s->{p})." ".$s->{i}.":".$s->{dport}." >> ".$s->{to};

    $self->mk_array((
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
    my $self = shift;
    
    my $s = shift;
    my $chain = shift // 'INPUT';

    $self->mk_array((
	'-I' , $chain,
	'-i' , $s->{i},
	'-p' , 'tcp --syn',
	'--dport' , $s->{dport},
	'-j' , 'ACCEPT'
	     ));
}

# Accept( { i => 'eth1' , dport => 22 , p => 'tcp' } );
sub Accept {
    my $self = shift;
    
    my $s = shift;
    my $chain = shift // 'INPUT';

    push @{$self->net->{services}->{$s->{p}}->{$s->{dport}}},
    "[$chain] Accept ".uc($s->{p})." > ".$s->{i}.":".$s->{dport};

    $self->mk_array((
	'-I' , $chain,
	'-i' , $s->{i},
	'-p' , $s->{p},
	'--dport' , $s->{dport},
	'-j' , 'ACCEPT'
	     ));
}

# Block( { i => 'eth1' , p => 'tcp' , dport => 53 } );
sub Block {
    my $self = shift;
    
    my $s = shift;
    my $chain = shift // 'INPUT';

    push @{$self->net->{services}->{$s->{p}}->{$s->{dport}}},
    "[$chain] Block ".uc($s->{p})." > ".$s->{i}.":".$s->{dport};

    $self->mk_array((
	'-I' , $chain,
	'-i' , $s->{i},
	'-p' , $s->{p},
	'--dport' , $s->{dport},
	'-j' , 'DROP'
	     ));
}

=doc BlockIP('9.9.9.9')
 $src = IP address
 $chain = Iptables Chain , default blacklist-ip
=cut
sub BlockIP {
    my $self  = shift;
    my $src   = shift;
    my $chain = shift // 'blacklist-ip';
    
    $self->mk_array((
	'-A' , 'INPUT',
	'-s' , $src,
	'-j' , $chain
	     ));
}

sub mk_array {
    my $self = shift;
    
    my @x = @_;
    my ($s,$t,$c) = ('',1,scalar(@x)/2);

    for (1 .. $c) {
	$s .= $x[$t-1].' '.$x[$t].' ';
	$t += 2;
    }

    $self->X($s);
}

sub Block_TOR {
    my $self = shift;
    my $TOR_List = 'https://www.dan.me.uk/torlist/';

    my $t = HTTP::Tiny->new->get($TOR_List)->{content};

    $self->X('-N block-tor');
    $self->X('-A block-tor -j DROP');

    for my $IP ( split '\n',$t ) {
	$self->X("-A INPUT -s $IP -j block-tor");
    }

}

sub Block_Country {
    my $self = shift;
    my $country = shift;

    my $url = 'http://www.ipdeny.com/ipblocks/data/countries/'.$country.'.zone';

    my $chain = "block-country-$country";

    $self->X("-N $chain");
    $self->X("-A $chain -j DROP");

    my $t = HTTP::Tiny->new->get($url)->{content};

    for my $IP ( split '\n',$t ) {
	$self->X("-A INPUT -s $IP -j $chain");
    }
}

sub Netstat {
    my $self = shift;
    
    my @a = qx(netstat -lntu);

    shift @a for 1 .. 2;

    for (@a) {
	chomp;
	my @v = split ' ',$_;
	my ($ip,$port) = split ':',$v[3];
	$self->net->{listen}->{$v[0]}->{$ip} = $port if $ip =~ /^\d/;
    }
}

sub ReadIF {
    my $self = shift;
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
    $self->sys->{dev} = \%result;

    ## Networks IPv6
    local $/;
    open( my $fh6, '<', '/proc/net/if_inet6' );
    $t = <$fh6>;
    close($fh6);

    my @a = split ' ',$t;
    for(1 .. scalar(@a)/6) {
	my $c = ($_*6)-1;
	$self->sys->{dev}->{$a[$c]}->{ipv6} = 1;
    }

    $self->conf->{init}->{devs} = { map { $_ => 0 } keys %{$self->sys->{dev}} };
}

sub Report {
    my $self = shift;
    
    say "Net :";
    for my $Net ( keys %{ $self->conf->{init}->{devs} } ) {
	say $self->conf->{init}->{devs}->{$Net} ? "\t$Net OK" : "\t$Net\tNo config";
    }

    say "iptables :";
    for my $proto (qw(tcp udp)) {
	next unless $self->net->{services}->{$proto};
	for my $S ( keys %{ $self->net->{services}->{$proto} } ) {
	    map { say "\t$_" } @{$self->net->{services}->{$proto}->{$S}};
	}
    }

    say "listen :";
    for my $proto (qw(tcp udp)) {
	next unless $self->net->{listen}->{$proto};
	say "\t[$proto]\t$_:".$self->net->{listen}->{$proto}->{$_} for
	    keys %{ $self->net->{listen}->{$proto} };
    }
}

1;
