#!/usr/local/bin/perl -w
### Rozhuk Ivan, 2011 - 2016
### dhcp perl server
### version 1.0

# required:
# /usr/ports/lang/p5-Switch
# /usr/ports/net/p5-Net-DHCP
# /usr/ports/devel/p5-Test-Benchmark
# /usr/ports/databases/p5-DBI
# /usr/ports/databases/p5-Class-DBI-mysql

# 2014.06: 	* fix: db_get_routing - send routes only in 121/249 option, do not mix with option 33
# 2016.01: 	* fix: Windows XP work with option 43
#		* fix: opt82 parse on new ugly swithes

use strict;
use utf8;
use warnings;
use threads;
use threads::shared;
use Socket;
use Switch;
use DBI;
use Net::DHCP::Packet;
use Net::DHCP::Constants;
use Benchmark ':hireswallclock';
use POSIX qw(setsid setuid strftime :signal_h);
use Getopt::Long;
use Sys::Syslog;
#require 'sys/syscall.ph';

binmode(STDOUT, ':utf8');

# settings, via command line or internal defined
my ($BIND_ADDR, $SERVER_PORT, $CLIENT_PORT, $MIRROR, $DHCP_SERVER_ID, $THREADS_COUNT, $DBDATASOURCE, $DBLOGIN, $DBPASS, $PIDFILE, $DEBUG);

# global variables
my ($RUNNING, $ADDR_BCAST, $ADDR_MIRROR, $SOCKET_RCV);

share($RUNNING);
#share($SOCKET_RCV);

&startpoint();

# this keeps the program alive or something after exec'ing perl scripts
END(){}
BEGIN(){}
{
    no warnings; *CORE::GLOBAL::exit = sub {die "fakeexit\nrc=" . shift() . "\n";};
};
eval q{exit};
if ($@) {exit unless $@ =~ /^fakeexit/;};

# generic signal handler to cause daemon to stop
sub signal_handler {
    logger("Function: " . (caller(0))[3]);
    $RUNNING = 0;
    close($SOCKET_RCV);
    $_->kill('KILL')->detach() foreach threads->list();
    #$_->join foreach threads->list();
}

sub startpoint {
    logger("Function: " . (caller(0))[3]);
    if ($#ARGV == - 1) {
        usage();
        return;
    }

    # set default settings values
    $BIND_ADDR = '0.0.0.0';
    $SERVER_PORT = '67';
    $CLIENT_PORT = '68';
    $DHCP_SERVER_ID = ''; # REQUIRED real IP for work!!!
    $MIRROR = undef;
    $DBDATASOURCE = 'mysql:dhcp:127.0.0.1';
    $DBLOGIN = 'dhcp';
    $DBPASS = 'dhcp';
    $THREADS_COUNT = 4;
    $PIDFILE = '/var/run/perl-dhcpd.pid';
    $DEBUG = undef;
    my $DAEMON = undef;

    GetOptions(
        'b=s'   => \$BIND_ADDR,
        'sp:i'  => \$SERVER_PORT,
        'cp:i'  => \$CLIENT_PORT,
        'id=s'  => \$DHCP_SERVER_ID,
        'm=s'   => \$MIRROR,
        't:i'   => \$THREADS_COUNT,
        'dbs=s' => \$DBDATASOURCE,
        'dbl=s' => \$DBLOGIN,
        'dbp=s' => \$DBPASS,
        'P:s'   => \$PIDFILE,
        'v:i'   => \$DEBUG,
        'd'     => \$DAEMON,
    );

    # untainte input
    if ($BIND_ADDR =~ /^(.*)$/) {$BIND_ADDR = $1;}
    if ($DHCP_SERVER_ID =~ /^(.*)$/) {$DHCP_SERVER_ID = $1;}
    if ($PIDFILE =~ /^(.*)$/) {$PIDFILE = $1;}

    if (defined($DHCP_SERVER_ID) == 0) {
        usage();
    }

    $SIG{INT} = $SIG{TERM} = $SIG{HUP} = \&signal_handler;
    # trap or ignore $SIG{PIPE}

    # Daemon behaviour
    # ignore any PIPE signal: standard behaviour is to quit process
    $SIG{PIPE} = 'IGNORE';

    openlog("dhcp-perl", "ndelay,pid", "local0");

    logger("BIND_ADDR: $BIND_ADDR, THREADS_COUNT: $THREADS_COUNT, PIDFILE: $PIDFILE");

    if (defined($DAEMON)) {
        $DEBUG = undef;
        daemonize();
    }

    main();
}

sub usage {
    logger("Function: " . (caller(0))[3]);
    print "Usage: dhcpd [options]\n\n";
    print " -b <ip>		ip address to bind (def: 0.0.0.0)\n";
    print " -sp <port>		port bind (def: 67)\n";
    print " -cp <port>		port to send reply directly to client (def: 68)\n";
    print " -id <ip>		ip addr DHCP server ID, REQUIRED!, MUST be real IP of server\n";
    print " -m <ip>		ip address to mirror all packets on 67 port\n";
    print " -t <threads>		number of thread, recomended: CPU cores * 2, (default 4)\n";
    print " -dbs			database data source: DriverName:database=database_name;host=hostname;port=port\n";
    print " -dbl			data base login\n";
    print " -dbp			data base password\n";
    print " -P <path>		name of PID-file for spawned process\n";
    print " -v <level>		print debug info, levels: 1, 2 (def: off)\n";
    print " -d			daemon mode\n";

    exit;
}

# sample logger
sub logger {
    syslog('info', $_[0]);
    if (defined($DEBUG) == 0) {return;}

    print STDOUT strftime "[%d/%b/%Y %H:%M:%S] ", localtime;
    print STDOUT $_[0] . "\n";
}

sub daemonize {
    logger("Function: " . (caller(0))[3]);
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)}; # Make %ENV safer
    #setuid(65534)		or die "Can't set uid: $!\n"; # nobody

    open(STDIN, "+>/dev/null") or die "Can't open STDIN: $!\n";
    open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!\n";
    open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!\n";
    defined(my $tm = fork) or die "Can't fork: $!\n";
    exit if $tm;
    setsid or die "Can't start a new session: $!\n";
    umask 0;

    logger("Daemon mode");
}

sub main {
    logger("Function: " . (caller(0))[3]);
    if (defined($BIND_ADDR) == 0) {return;}

    # write PID to file
    if (defined($PIDFILE)) {
        open FILE, "> $PIDFILE" || logger("PID file save error: $!");
        print FILE "$$\n";
        close FILE;
    }

    $RUNNING = 1;

    # broadcast address
    $ADDR_BCAST = sockaddr_in($CLIENT_PORT, INADDR_BROADCAST);# sockaddr_in($CLIENT_PORT, inet_aton('255.255.255.255'))

    # set mirror address if defimed
    if (defined($MIRROR)) {# traff mirroring
        $ADDR_MIRROR = sockaddr_in($SERVER_PORT, inet_aton($MIRROR));
    }

    # open listening socket
    socket($SOCKET_RCV, PF_INET, SOCK_DGRAM, getprotobyname('udp')) || die "Socket creation error: $@\n";
    bind($SOCKET_RCV, sockaddr_in($SERVER_PORT, inet_aton($BIND_ADDR))) || die "bind: $!";

    # start threads
    for my $i (1 .. ($THREADS_COUNT - 1)) {
        threads->create({ 'context' => 'void' }, \&request_loop);
    }

    ### Collect the bits and pieces! ...
    #$_->join foreach threads->list();
    #$_->detach foreach threads->list();

    # and handle request with other threads
    request_loop();

    # delete PID file on exit
    if (defined($PIDFILE)) {
        unlink($PIDFILE);
    }

    logger("Main: END!");

    closelog();
}

sub request_loop {
    logger("Function: " . (caller(0))[3]);
    my ($buf, $fromaddr, $dhcpreq); # recv data
    my $dbh; # database connect
    my ($t0, $t1, $td); # perfomance data
    my $tid = threads->tid(); # thread ID

    logger("Thread ($tid): START");

    # each thread make its own connection to DB
    # connect($data_source, $username, $password, \%attr)
    # dbi:DriverName:database=database_name;host=hostname;port=port

    until($dbh = DBI->connect("DBI:".$DBDATASOURCE, $DBLOGIN, $DBPASS)){
        logger("Thread ($tid): Could not connect to database: $DBI::errstr");
        logger("Thread ($tid): Sleeping 10 sec to retry");
        sleep(10);
    }

    if (defined($dbh) == 0) {
        logger("Could not connect to database: $DBI::errstr");
        thread_exit(1);
    }

    $dbh->{mysql_auto_reconnect} = 1;

    if ($tid != 0) {
        # disable signals receiving on creted threads and set handler for KILL signal
        my $sigset = POSIX::SigSet->new(SIGINT, SIGTERM, SIGHUP);    # define the signals to block
        my $old_sigset = POSIX::SigSet->new;        # where the old sigmask will be kept
        unless (defined sigprocmask(SIG_BLOCK, $sigset, $old_sigset)) {die "Could not unblock SIGINT\n";}

        $SIG{KILL} = sub {
            logger("Thread ($tid): END by sig handler");
            $dbh->disconnect;
            thread_exit(0);
        };
    }

    while ($RUNNING == 1) {
        $buf = undef;

        eval {
            # catch fatal errors
            # receive packet
            $fromaddr = recv($SOCKET_RCV, $buf, 16384, 0) || logger("Thread ($tid) recv err: $!");

            next if ($!); # continue loop if an error occured

            # filter to small packets
            next if (length($buf) < 236); # 300

            if (defined($DEBUG)) {
                $t0 = Benchmark->new;
            }

            # parce data to dhcp structes
            $dhcpreq = new Net::DHCP::Packet($buf);

            # filter bad params in head
            next if ($dhcpreq->op() != BOOTREQUEST || $dhcpreq->isDhcp() == 0);
            next if ($dhcpreq->htype() != HTYPE_ETHER || $dhcpreq->hlen() != 6);

            # bad DHCP message!
            next if (defined($dhcpreq->getOptionRaw(DHO_DHCP_MESSAGE_TYPE())) == 0);

            # Is message for us?
            next if (defined($dhcpreq->getOptionRaw(DHO_DHCP_SERVER_IDENTIFIER())) && $dhcpreq->getOptionValue(DHO_DHCP_SERVER_IDENTIFIER()) ne $DHCP_SERVER_ID);

            # RRAS client, ignory them
            next if (defined($dhcpreq->getOptionRaw(DHO_USER_CLASS())) && $dhcpreq->getOptionRaw(DHO_USER_CLASS()) eq "RRAS.Microsoft");

            # send duplicate of received packet to mirror
            if (defined($ADDR_MIRROR)) {
                send($SOCKET_RCV, $buf, 0, $ADDR_MIRROR) || logger("send mirr error: $!");
            }

            # print received packed
            if (defined($DEBUG)) {
                my ($port, $addr) = unpack_sockaddr_in($fromaddr);
                my $ipaddr = inet_ntoa($addr);
                logger("Thread $tid: Got a packet src = $ipaddr:$port length = " . length($buf));
                if ($DEBUG > 1) {
                    logger($dhcpreq->toString());
                }
            }

            # handle packet
            switch ($dhcpreq->getOptionValue(DHO_DHCP_MESSAGE_TYPE())) {
                case DHCPDISCOVER {
                    #-> DHCPOFFER
                    db_log_detailed($dbh, $dhcpreq);
                    handle_discover($dbh, $fromaddr, $dhcpreq);
                }
                case DHCPREQUEST {
                    #-> DHCPACK/DHCPNAK
                    db_log_detailed($dbh, $dhcpreq);
                    handle_request($dbh, $fromaddr, $dhcpreq);
                }
                case DHCPDECLINE {
                    db_log_detailed($dbh, $dhcpreq);
                    handle_decline($dbh, $fromaddr, $dhcpreq);
                }
                case DHCPRELEASE {
                    db_log_detailed($dbh, $dhcpreq);
                    handle_release($dbh, $fromaddr, $dhcpreq);
                }
                case DHCPINFORM {
                    #-> DHCPACK
                    db_log_detailed($dbh, $dhcpreq);
                    handle_inform($dbh, $fromaddr, $dhcpreq);
                }
            }

            if (defined($DEBUG)) {
                $t1 = Benchmark->new;
                $td = timediff($t1, $t0);
                logger("Thread $tid: the code took: " . timestr($td));
            }
        }; # end of 'eval' blocks
        if ($@) {
            logger("Thread $tid: Caught error in main loop: $@");
        }
    }

    $dbh->disconnect;

    thread_exit(0);
}

sub thread_exit($) {
    logger("Function: " . (caller(0))[3]);
    my $tid = threads->tid(); # thread ID

    logger("Thread ($tid): END code: " . $_[0]);

    threads->exit($_[0]) if threads->can('exit');
    exit($_[0]);
}

sub send_reply {
    logger("Function: " . (caller(0))[3]);
    #my $fromaddr = $_[0];
    #my $dhcpreq = $_[1];
    #my $dhcpresp = $_[2];
    my ($dhcpresppkt, $toaddr);

    # add last!!!!
    if (defined($_[1]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()))) {
        $_[2]->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $_[1]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()));
    }

    $dhcpresppkt = $_[2]->serialize();
    #if (length($dhcpresppkt) < 548) {
    #	$dhcpresppkt .= "\0" x (548 - length($dhcpresppkt));
    #}

    if ($_[1]->giaddr() eq '0.0.0.0') {
        # client local, not relayed
        if ($_[2]->DHO_DHCP_MESSAGE_TYPE() == DHCPNAK) {# allways broadcast DHCPNAK
            $toaddr = $ADDR_BCAST;
        }
        else {
            if ($_[1]->ciaddr() eq '0.0.0.0') {
                # ALL HERE NON RFC 2131 4.1 COMPLIANT!!!
                # perl can not send to hw addr unicaset with ip 0.0.0.0, and we send broadcast
                if ($_[1]->flags() == 0 || 1) {
                    # send unicast XXXXXXXXX - flags ignored!
                    # here we mast send unicast to hw addr, ip 0.0.0.0
                    my ($port, $addr) = unpack_sockaddr_in($_[0]);
                    my $ipaddr = inet_ntoa($addr);

                    if ($ipaddr eq '0.0.0.0') {
                        $toaddr = $ADDR_BCAST;
                    }
                    else {# giaddr and ciaddr is zero but we know ip addr from received packet
                        $toaddr = sockaddr_in($CLIENT_PORT, $addr);
                    }
                }
                else {
                    # only this comliant to rfc 2131 4.1
                    $toaddr = $ADDR_BCAST;
                }
            }
            else {# client have IP addr, send unicast
                $toaddr = sockaddr_in($CLIENT_PORT, $_[1]->ciaddrRaw());
            }
        }
    }
    else {# send to relay
        $toaddr = sockaddr_in($SERVER_PORT, $_[1]->giaddrRaw());
    }
    send($SOCKET_RCV, $dhcpresppkt, 0, $toaddr) || logger("send error: $!");

    if (defined($DEBUG)) {
        my ($port, $addr) = unpack_sockaddr_in($toaddr);
        my $ipaddr = inet_ntoa($addr);
        logger("Sending response to = $ipaddr:$port length = " . length($dhcpresppkt));
        if ($DEBUG > 1) {
            logger($_[1]->toString());
        }
    }

    # send copy of packet to mirror, if specified
    if (defined($ADDR_MIRROR)) {
        send($SOCKET_RCV, $dhcpresppkt, 0, $ADDR_MIRROR) || logger("send mirr error: $!");
    }
}

# Generate responce DHCP packet from request DHCP packet
sub GenDHCPRespPkt {
    logger("Function: " . (caller(0))[3]);
    #my $dhcpreq = $_[0];

    my $dhcpresp = new Net::DHCP::Packet(Op => BOOTREPLY(),
            Htype                           => $_[0]->htype(),
            Hlen                            => $_[0]->hlen(),
            # Hops                          => $_[0]->hops(), # - not copyed in responce
            Xid                             => $_[0]->xid(),
            Secs                            => $_[0]->secs(),
            Flags                           => $_[0]->flags(),
            Ciaddr                          => $_[0]->ciaddr(),
            #Yiaddr                         => '0.0.0.0',
            Siaddr                          => $_[0]->siaddr(),
            Giaddr                          => $_[0]->giaddr(),
            Chaddr                          => $_[0]->chaddr(),
            DHO_DHCP_MESSAGE_TYPE()         => DHCPACK, # must be owerwritten
            DHO_DHCP_SERVER_IDENTIFIER()    => $DHCP_SERVER_ID
        );
    return ($dhcpresp);
}

sub BuffToHEX($) {
    logger("Function: " . (caller(0))[3]);
    my $buf = shift;

    #$buf =~ s/([[:^print:]])/ sprintf q[\x%02X], ord $1 /eg;  # printable text
    $buf =~ s/(.)/sprintf("%02x", ord($1))/eg;

    return ($buf);
}

# convert RelayAgent options to human readable
sub unpackRelayAgent(%) {
    logger("Function: " . (caller(0))[3]);
    my @SubOptions = @_;
    my $buf;

    for (my $i = 0; defined($SubOptions[$i]); $i += 2) {
        $buf .= "($SubOptions[$i])=" . BuffToHEX($SubOptions[($i + 1)]) . ', ';
    }

    return ($buf);
}

# get relay agent options from dhcp packet
sub GetRelayAgentOptions($$$$$$) {
    logger("Function: " . (caller(0))[3]);
    #my $dhcpreq = $_[0];
    #my $dhcp_opt82_vlan_id = $_[1];
    #my $dhcp_opt82_unit_id = $_[2];
    #my $dhcp_opt82_port_id = $_[3];
    #my $dhcp_opt82_chasis_id = $_[4];
    #my $dhcp_opt82_subscriber_id = $_[5];
    my @RelayAgent;

    # Set return values.
    $_[1] = '';
    $_[2] = '';
    $_[3] = '';
    $_[4] = '';
    $_[5] = '';

    # no options, return
    return(0) if (defined($_[0]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS())) == 0);


    @RelayAgent = $_[0]->decodeRelayAgent($_[0]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()));

    logger("RelayAgent: " . @RelayAgent);

    for (my $i = 0; defined($RelayAgent[$i]); $i += 2) {
        switch ($RelayAgent[$i]){
            case 1 {
                # Circuit ID
                logger("RelayAgent Circuit ID: " . $RelayAgent[($i + 1)]);
                next if (length($RelayAgent[($i + 1)]) < 4);
                # first bytes must be: 00 04
                #$_[1] = unpack('n', substr($RelayAgent[($i + 1)], -4, 2)); # may be 's'
                $RelayAgent[($i + 1)] =~ /(\d+)(?=\ )/;
                $_[1] = $1;
                logger("RelayAgent VLan: " . $_[1]);
                #$_[2] = unpack('C', substr($RelayAgent[($i + 1)], -2, 1));
                $RelayAgent[($i + 1)] =~ /(\d+)(?=\/\d+:)/;
                $_[2] = $1;
                logger("RelayAgent Unit: " . $_[2]);
                #$_[3] = unpack('C', substr($RelayAgent[($i + 1)], -1, 1));
                $RelayAgent[($i + 1)] =~ /(\d+)(?=:)/;
                $_[3] = $1;
                logger("RelayAgent Port: " . $_[3]);
            }
            case 2 {
                # Remote ID
                next if (length($RelayAgent[($i + 1)]) < 6);
                # first bytes must be: 00 06 or 01 06 or 02 xx
                # first digit - format/data type, second - len
                $_[4] = FormatMAC(unpack("H*", substr($RelayAgent[($i + 1)], - 6, 6)));
                logger("RelayAgent 4: " . $_[4]);
                # 02 xx - contain vlan num, undone
            }
            case 6 {
                # Subscriber ID
                $_[5] = $RelayAgent[($i + 1)];
                logger("RelayAgent 5: " . $_[5]);
            }
        }
    }

    return (1);
}

# change mac addr format from "abcdefg" to "a:b:c:d:e:f:g"
sub FormatMAC {
    logger("Function: " . (caller(0))[3]);
    $_[0] =~ /([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})/i;
    return (lc(join(':', $1, $2, $3, $4, $5, $6)));
}

# http://cpansearch.perl.org/src/SARENNER/Net-IPAddress-1.10/IPAddress.pm
#sub parseIPtoNumber {
#return (unpack("N", pack("C4", split(/\./, $_[0])))); # C4 = CCCC
#}

# mask to bits
# http://milanweb.net/uni/old/scripting.html
sub subnetBits {
    logger("Function: " . (caller(0))[3]);
    my $m = unpack("N", pack("C4", split(/\./, $_[0]))); # parseIPtoNumber
    my $v = pack("L", $m);
    my $bcnt = 0;

    foreach (0 .. 31) {
        if (vec($v, $_, 1) == 1) {
            $bcnt++;
        }
    }

    return ($bcnt);
}

# (121) Classless-Static-Route / (249) MSFT - Classless route
# by Rozhuk Ivan 2011
# RFC 3442
# based on:
# http://www.linuxconfig.net/index.php/linux-manual/network/203-transfer-of-static-routes-to-dhcp.html
# http://www.linux.by/wiki/index.php/FAQ_DHCP_routes
# Syntax: mk_classless_routes_bin_mask($net, $mask, $gw)
# example: mk_classless_routes_bin_mask('192.168.1.0', '255.255.255.0', '192.168.0.254')
sub mk_classless_routes_bin_mask {
    logger("Function: " . (caller(0))[3]);
    #my $net = $_[0];
    #my $mask = $_[1];
    #my $gw = $_[2];

    return (mk_classless_routes_bin_prefixlen($_[0], subnetBits($_[1]), $_[2]));
}

# Syntax: mk_classless_routes_bin_prefixlen($net, $prefixlen, $gw)
# example: mk_classless_routes_bin_prefixlen('192.168.1.0', 24, '192.168.0.254')
sub mk_classless_routes_bin_prefixlen {
    logger("Function: " . (caller(0))[3]);
    #my $net = $_[0];
    #my $prefixlen = $_[1];
    #my $gw = $_[2];
    my $str;

    $str = pack('C', $_[1]);

    if ($_[1] > 0) {
        my ($s1, $s2, $s3, $s4) = split(/\./, $_[0]);
        $str .= pack('C', $s1);
        $str .= pack('C', $s2) if ($_[1] > 8);
        $str .= pack('C', $s3) if ($_[1] > 16);
        $str .= pack('C', $s4) if ($_[1] > 24);
    }

    $str .= pack('CCCC', split(/\./, $_[2]));

    return ($str);
}

sub handle_discover {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $fromaddr  = $_[1];
    #my $dhcpreq = $_[2];
    my ($dhcpresp);

    $dhcpresp = GenDHCPRespPkt($_[2]);
    $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPOFFER);

    if (db_get_requested_data($_[0], $_[2], $dhcpresp, $_[1]) == 1) {
        send_reply($_[1], $_[2], $dhcpresp);
        db_lease_offered($_[0], $_[2], $dhcpresp);
    }
    else {# if AUTO_CONFIGURE (116) supported - send disable generate link local addr
        if (defined($_[2]->getOptionRaw(DHO_AUTO_CONFIGURE))
            && $_[2]->getOptionValue(DHO_AUTO_CONFIGURE()) != 0) {
            $dhcpresp->addOptionValue(DHO_AUTO_CONFIGURE(), 0);
            send_reply($_[1], $_[2], $dhcpresp);
        }
    }
}

sub handle_request {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $fromaddr  = $_[1];
    #my $dhcpreq = $_[2];
    my ($dhcpresp);

    $dhcpresp = GenDHCPRespPkt($_[2]);

    if (db_get_requested_data($_[0], $_[2], $dhcpresp, $_[1]) == 1) {
        if ((defined($_[2]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) &&
            $_[2]->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS()) ne $dhcpresp->yiaddr()) ||
            (defined($_[2]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) == 0
                && $_[2]->ciaddr() ne $dhcpresp->yiaddr())) {
            # NAK if requested addr not equal IP addr in DB
            $dhcpresp->ciaddr('0.0.0.0');
            $dhcpresp->yiaddr('0.0.0.0');
            $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPNAK);
            db_lease_nak($_[0], $_[2]);
        }
        else {
            $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);
            db_lease_success($_[0], $_[2]);
        }

        send_reply($_[1], $_[2], $dhcpresp);
    }
}

sub handle_decline {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $fromaddr  = $_[1];
    #my $dhcpreq = $_[2];

    db_lease_decline($_[0], $_[2]);
}

sub handle_release {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $fromaddr  = $_[1];
    #my $dhcpreq = $_[2];

    db_lease_release($_[0], $_[2]);
}

sub handle_inform {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $fromaddr  = $_[1];
    #my $dhcpreq = $_[2];
    my ($dhcpreqparams, $dhcpresp);

    $dhcpresp = GenDHCPRespPkt($_[2]);
    $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);

    if (db_get_requested_data($_[0], $_[2], $dhcpresp, $_[1]) == 0) {
        $dhcpreqparams = $_[2]->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST());
        static_data_to_reply($dhcpreqparams, $dhcpresp);
    }

    send_reply($_[1], $_[2], $dhcpresp);
}

sub static_data_to_reply {
    logger("Function: " . (caller(0))[3]);
    #my $dhcpreqparams = $_[0];
    #my $dhcpresp = $_[1];

    # do not add params if not requested
    return() if (defined($_[0]) == 0);

    if (index($_[0], DHO_ROUTER_DISCOVERY()) != - 1) {
        $_[1]->addOptionValue(DHO_ROUTER_DISCOVERY(), 0);
    }

    if (index($_[0], DHO_NTP_SERVERS()) != - 1) {
        $_[1]->addOptionValue(DHO_NTP_SERVERS(), '8.8.8.8 8.8.8.8');
    }

    if (index($_[0], DHO_NETBIOS_NODE_TYPE()) != - 1) {
        $_[1]->addOptionValue(DHO_NETBIOS_NODE_TYPE(), 8); # H-Node
    }

    # Option 43 must be last for Windows XP proper work
    # https://support.microsoft.com/en-us/kb/953761
    if (index($_[0], DHO_VENDOR_ENCAPSULATED_OPTIONS()) != - 1) {
        # 001 - NetBIOS over TCP/IP (NetBT): 00000002 (2) - disabled
        # 002 - Release DHCP Lease on Shutdown: 00000001 (1) - enabled
        # 255 - END
        $_[1]->addOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS(), "\x01\x04\x00\x00\x00\x02\x02\x04\x00\x00\x00\x01\xff");
    }
}

sub db_get_requested_data {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreq = $_[1];
    #my $dhcpresp = $_[2];
    #my $fromaddr = $_[3];
    my ($port, $addr) = unpack_sockaddr_in($_[3]);
    my (
        $mac,
        $sth,
        $dhcpreqparams,
        $result
    );
    my (
        $dhcp_opt82_vlan_id,
        $dhcp_opt82_unit_id,
        $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id,
        $dhcp_opt82_subscriber_id
    );

    # change hw addr format
    $mac = FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
    $dhcpreqparams = $_[1]->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST());

    $sth = $_[0]->prepare("SELECT * FROM `clients`, `subnets` WHERE `clients`.`mac` = '$mac' AND `clients`.`subnet_id` = `subnets`.`subnet_id` LIMIT 1;");

    if ($DEBUG > 1) {
        logger($_[1]->toString());
        logger("Thread $tid: Got a packet src = $ipaddr:$port");
        logger("SELECT * FROM `clients`, `subnets` WHERE `clients`.`mac` = '$mac' AND `clients`.`subnet_id` = `subnets`.`subnet_id` LIMIT 1;");
    }
    $sth->execute();
    if ($sth->rows()) {
        $result = $sth->fetchrow_hashref();
        $_[2]->yiaddr($result->{ip});
        db_data_to_reply($result, $dhcpreqparams, $_[2]);
        db_get_routing($_[0], $dhcpreqparams, $result->{subnet_id}, $_[2]);
        static_data_to_reply($dhcpreqparams, $_[2]);
        $sth->finish();
        return (1);
    }

    if (GetRelayAgentOptions($_[1], $dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id)) {
        # try work as traditional DHCP: find scope by opt82 info, then give some free addr

        if ($dhcp_opt82_chasis_id ne '') {
            $sth = $_[0]->prepare(
                "SELECT
                    *
                FROM
                    `subnets`,
                    `ips`
                WHERE
                    `subnets`.`vlan_id` = '$dhcp_opt82_vlan_id'
                AND
                    `subnets`.`type` = 'guest'
                AND
                    `ips`.`lease_time` = ''
                LIMIT 1;
                "
            );
            if ($DEBUG > 1) {
                    logger("SELECT * FROM `subnets`, `ips` WHERE `subnets`.`vlan_id` = '$dhcp_opt82_vlan_id' AND `subnets`.`type` = 'guest' AND `ips`.`lease_time` = '' LIMIT 1;");
            }
            $sth->execute();

            if ($sth->rows()) {
                $result = $sth->fetchrow_hashref();

                db_data_to_reply($result, $dhcpreqparams, $_[2]);

                db_get_routing($_[0], $dhcpreqparams, $result->{subnet_id}, $_[2]);

                static_data_to_reply($dhcpreqparams, $_[2]);

                #######################$_[2]->yiaddr($result->{ip});

                $sth->finish();
                return (1);
            }
            # subnet_id + dhcp client id = client lease
            # From: dhcp_guest_leases
        }
    }

    $sth->finish();

    return (0);
}

sub db_data_to_reply {
    logger("Function: " . (caller(0))[3]);
    #my $result = $_[0];
    #my $dhcpreqparams = $_[1];
    #my $dhcpresp = $_[2];


    # http://www.tcpipguide.com/free/t_DHCPLeaseLifeCycleOverviewAllocationReallocationRe.htm
    # DHCPDiscover / DHCPRequest / DHCPOffer
    #$_[0]->{dhcp_lease_time} = 180;
    if (defined($_[0]->{dhcp_lease_time})) {
        $_[2]->addOptionValue(DHO_DHCP_LEASE_TIME(), $_[0]->{dhcp_lease_time});

        # function (typically 50%) of the full configured duration (or lease time) for a client's lease
        if (defined($_[0]->{dhcp_renewal})) {
            $_[2]->addOptionValue(DHO_DHCP_RENEWAL_TIME(), $_[0]->{dhcp_renewal});
            #} else {
            #	$_[2]->addOptionValue(DHO_DHCP_RENEWAL_TIME(), ($_[0]->{dhcp_lease_time}/2));
        }

        # function (typically 87.5%) of the full configured duration (or lease time) for a client's lease
        if (defined($_[0]->{dhcp_rebind_time})) {
            $_[2]->addOptionValue(DHO_DHCP_REBINDING_TIME(), $_[0]->{dhcp_rebind_time});
            #} else {
            #	$_[2]->addOptionValue(DHO_DHCP_REBINDING_TIME(), ($_[0]->{dhcp_lease_time}*7/8));
        }
    }


    # do not add params if not requested
    return() if (defined($_[1]) == 0);

    if (index($_[1], DHO_SUBNET_MASK()) != - 1 && defined($_[0]->{mask})) {
        $_[2]->addOptionValue(DHO_SUBNET_MASK(), $_[0]->{mask});
    }

    if (index($_[1], DHO_ROUTERS()) != - 1 && defined($_[0]->{gateway})) {
        $_[2]->addOptionValue(DHO_ROUTERS(), $_[0]->{gateway});
    }

    if (index($_[1], DHO_DOMAIN_NAME_SERVERS()) != - 1 && defined($_[0]->{dns1})) {
        $_[2]->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), "$_[0]->{dns1} $_[0]->{dns2}");
    }

    if (index($_[1], DHO_HOST_NAME()) != - 1 && defined($_[0]->{hostname})) {
        $_[2]->addOptionValue(DHO_HOST_NAME(), $_[0]->{hostname});
    }

    if (index($_[1], DHO_DOMAIN_NAME()) != - 1 && defined($_[0]->{domain})) {
        $_[2]->addOptionValue(DHO_DOMAIN_NAME(), $_[0]->{domain});
    }
}

sub db_get_routing {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreqparams = $_[1];
    #my $subnet_id = $_[2];
    #my $dhcpresp = $_[3];
    my (
        $sth,
        $opt33Enbled,
        $optClasslessRoutesCode
    );

    # do not add routes if not requested
    return() if (defined($_[1]) == 0);

    $opt33Enbled = index($_[1], DHO_STATIC_ROUTES());
    if ($opt33Enbled == - 1) {
        $opt33Enbled = undef;
    }

    $optClasslessRoutesCode = index($_[1], 121);
    if ($optClasslessRoutesCode == - 1) {
        $optClasslessRoutesCode = index($_[1], 249); # MSFT
        if ($optClasslessRoutesCode == - 1) {
            $optClasslessRoutesCode = undef;
        }
        else {
            $opt33Enbled = undef;
            $optClasslessRoutesCode = 249;
        }
    }
    else {
        $opt33Enbled = undef;
        $optClasslessRoutesCode = 121;
    }

    if (defined($opt33Enbled) == 0 && defined($optClasslessRoutesCode) == 0) {
        # nothink to do, return
        return ();
    }

    $sth = $_[0]->prepare("SELECT `destination`, `mask` `gateway` FROM `subnets_routes` WHERE `subnet_id` = '$_[2]' LIMIT 30;");

    if ($DEBUG > 1) {
        logger("SELECT `destination`, `mask` `gateway` FROM `subnets_routes` WHERE `subnet_id` = '$_[2]' LIMIT 30;");
    }

    $sth->execute();
    if ($sth->rows()) {
        my $ref;
        my $row;
        my $opt33_data = undef; # routes to single hosts
        my $opt_classless_routes_data = undef; # routes to nets

        $ref = $sth->fetchall_arrayref;
        foreach $row (@{$ref}) {
            if (defined($opt33Enbled) && @$row[1] eq '255.255.255.255') {
                # pack dst
                $opt33_data .= pack('CCCC', split(/\./, @$row[0]));

                # pack gw
                $opt33_data .= pack('CCCC', split(/\./, @$row[2]));
            }
            if (defined($optClasslessRoutesCode)) {
                $opt_classless_routes_data .= mk_classless_routes_bin_mask(@$row[0], @$row[1], @$row[2]);
            }
        }

        if (defined($opt33_data)) {# add option
            $_[3]->addOptionRaw(DHO_STATIC_ROUTES(), $opt33_data);
        }

        if (defined($opt_classless_routes_data)) {# add option
            $_[3]->addOptionRaw($optClasslessRoutesCode, $opt_classless_routes_data);
        }
    }
    $sth->finish();
}

sub db_lease_offered {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreq = $_[1];
    #my $dhcpresp = $_[2];
    my ($mac, $sth);

    # change hw addr format
    $mac = FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
    ####
    $sth = $_[0]->prepare(
        "UPDATE
            `ips`
        SET
            `lease_time` = UNIX_TIMESTAMP()+3600
        WHERE
            `ip` = '$_[2]->yiaddr';
        "
    );

    if ($DEBUG > 1) {
        logger("UPDATE `ips` SET `lease_time` = UNIX_TIMESTAMP()+3600 WHERE `ip` = '$_[2]->yiaddr';");
    }

    $sth->execute();
    $sth->finish();

    return (0);
}

sub db_lease_nak {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreq = $_[1];
    my ($mac, $sth);

    # change hw addr format
    $mac = FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
    ####
    $sth = $_[0]->prepare("");
    $sth->execute();
    $sth->finish();

    return (0);
}

sub db_lease_decline {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreq = $_[1];
    my ($mac, $sth);
    my (
        $dhcp_opt82_vlan_id,
        $dhcp_opt82_unit_id,
        $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id,
        $dhcp_opt82_subscriber_id
    );
    my (
        $client_ip,
        $gateway_ip,
        $client_ident,
        $requested_ip,
        $hostname,
        $dhcp_vendor_class,
        $dhcp_user_class
    );

    # change hw addr format
    $mac = FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));

    GetRelayAgentOptions(
        $_[1],
        $dhcp_opt82_vlan_id,
        $dhcp_opt82_unit_id,
        $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id,
        $dhcp_opt82_subscriber_id
    );

    $client_ip = $_[1]->ciaddr;
    $gateway_ip = $_[1]->giaddr;
    $client_ident = defined($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) ? BuffToHEX($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) : '';
    $requested_ip = defined($_[1]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) ? $_[1]->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS()) : '';
    $hostname = defined($_[1]->getOptionRaw(DHO_HOST_NAME())) ? $_[1]->getOptionValue(DHO_HOST_NAME()) : '';
    $dhcp_vendor_class = defined($_[1]->getOptionRaw(DHO_VENDOR_CLASS_IDENTIFIER())) ? $_[1]->getOptionValue(DHO_VENDOR_CLASS_IDENTIFIER()) : '';
    $dhcp_user_class = defined($_[1]->getOptionRaw(DHO_USER_CLASS())) ? $_[1]->getOptionRaw(DHO_USER_CLASS()) : '';

    ####
    $sth = $_[0]->prepare(
        "INSERT INTO
            `dhcp_log`
            (`created`,`client_mac`,`client_ip`,`gateway_ip`,`client_ident`,`requested_ip`,`hostname`,
            `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`,
            `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`)
         VALUES
            (NOW(),'$mac','$client_ip','$gateway_ip','$client_ident','$requested_ip','$hostname',
            '$dhcp_vendor_class','$dhcp_user_class','$dhcp_opt82_chasis_id','$dhcp_opt82_unit_id',
            '$dhcp_opt82_port_id','$dhcp_opt82_vlan_id','$dhcp_opt82_subscriber_id');
        "
    );

    if ($DEBUG > 1) {
        logger("INSERT INTO `dhcp_log` (`created`,`client_mac`,`client_ip`,`gateway_ip`,`client_ident`,`requested_ip`,`hostname`, `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`, `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`) VALUES (NOW(),'$mac','$client_ip','$gateway_ip','$client_ident','$requested_ip','$hostname', '$dhcp_vendor_class','$dhcp_user_class','$dhcp_opt82_chasis_id','$dhcp_opt82_unit_id', '$dhcp_opt82_port_id','$dhcp_opt82_vlan_id','$dhcp_opt82_subscriber_id');");
    }

    $sth->execute();
    $sth->finish();

    return (0);
}

sub db_lease_release {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreq = $_[1];
    my ($mac, $sth);

    # change hw addr format
    $mac = FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
    ####
    $sth = $_[0]->prepare(
        "UPDATE
            `ips`
        SET
            `lease_time` = '',
            `mac` = NULL
        WHERE
            `mac` ='$mac';
        "
    );

    if ($DEBUG > 1) {
        logger("UPDATE `ips` SET `lease_time` = '', `mac` = NULL WHERE `mac` ='$mac';");
    }

    $sth->execute();
    $sth->finish();

    return (0);
}

sub db_lease_success {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreq = $_[1];
    my ($mac, $sth, $result);
    my ($dhcp_opt82_vlan_id,
        $dhcp_opt82_unit_id,
        $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id,
        $dhcp_opt82_subscriber_id,
        $dhcp_vendor_class,
        $dhcp_user_class
    );

    # change hw addr format
    $mac = FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));

    GetRelayAgentOptions(
        $_[1],
        $dhcp_opt82_vlan_id,
        $dhcp_opt82_unit_id,
        $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id,
        $dhcp_opt82_subscriber_id
    );

    $dhcp_vendor_class = defined($_[1]->getOptionRaw(DHO_VENDOR_CLASS_IDENTIFIER())) ? $_[1]->getOptionValue(DHO_VENDOR_CLASS_IDENTIFIER()) : '';
    $dhcp_user_class = defined($_[1]->getOptionRaw(DHO_USER_CLASS())) ? $_[1]->getOptionRaw(DHO_USER_CLASS()) : '';

    $sth = $_[0]->prepare(
        "UPDATE
            `ips`
        SET
            `lease_time` = UNIX_TIMESTAMP()+3600,
            `mac` ='$mac'
        WHERE
            `ip` = (
                SELECT
                    `ip`
                FROM
                    `clients`
                WHERE
                    `mac` = '$mac'
                AND
                    `subnet_id` = (
                        SELECT
                            `subnet_id`
                        FROM
                            `subnets`
                        WHERE
                            `vlan_id` = $dhcp_opt82_vlan_id
                        AND `type` != 'guest'
                    )
            );
        "
    );

    if ($DEBUG > 1) {
        logger("UPDATE `ips` SET `lease_time` = UNIX_TIMESTAMP()+3600, `mac` ='$mac' WHERE `ip` = (SELECT `ip` FROM `clients` WHERE `mac` = '$mac' AND `subnet_id` = (SELECT `subnet_id` FROM `subnets` WHERE `vlan_id` = $dhcp_opt82_vlan_id AND `type` != 'guest'));");
    }

    $sth->execute();
    $sth->finish();
}

sub db_log_detailed {
    logger("Function: " . (caller(0))[3]);
    #my $dbh = $_[0];
    #my $dhcpreq = $_[1];
    my ($mac, $sth);
    my (
        $dhcp_opt82_vlan_id,
        $dhcp_opt82_unit_id,
        $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id,
        $dhcp_opt82_subscriber_id
    );
    my (
        $client_ip,
        $gateway_ip,
        $client_ident,
        $requested_ip,
        $hostname,
        $dhcp_vendor_class,
        $dhcp_user_class
    );

    # change hw addr format
    $mac = FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));

    GetRelayAgentOptions(
        $_[1],
        $dhcp_opt82_vlan_id,
        $dhcp_opt82_unit_id,
        $dhcp_opt82_port_id,
        $dhcp_opt82_chasis_id,
        $dhcp_opt82_subscriber_id
    );

    $client_ip = $_[1]->ciaddr;
    $gateway_ip = $_[1]->giaddr;
    $client_ident = defined($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) ? BuffToHEX($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) : '';
    $requested_ip = defined($_[1]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) ? $_[1]->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS()) : '';
    $hostname = defined($_[1]->getOptionRaw(DHO_HOST_NAME())) ? $_[1]->getOptionValue(DHO_HOST_NAME()) : '';
    $dhcp_vendor_class = defined($_[1]->getOptionRaw(DHO_VENDOR_CLASS_IDENTIFIER())) ? $_[1]->getOptionValue(DHO_VENDOR_CLASS_IDENTIFIER()) : '';
    $dhcp_user_class = defined($_[1]->getOptionRaw(DHO_USER_CLASS())) ? $_[1]->getOptionRaw(DHO_USER_CLASS()) : '';

    $sth = $_[0]->prepare(
        "INSERT INTO `dhcp_log`
            (`created`,`client_mac`,`client_ip`,`gateway_ip`,`client_ident`,`requested_ip`,`hostname`,
            `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`,
            `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`)
        VALUES
            (NOW(),'$mac','$client_ip','$gateway_ip','$client_ident','$requested_ip','$hostname',
            '$dhcp_vendor_class','$dhcp_user_class','$dhcp_opt82_chasis_id','$dhcp_opt82_unit_id',
            '$dhcp_opt82_port_id','$dhcp_opt82_vlan_id','$dhcp_opt82_subscriber_id')
        ON DUPLICATE KEY UPDATE
            `client_ip`                 = '$client_ip',
            `client_ident`              = '$client_ident',
            `requested_ip`              = '$requested_ip',
            `hostname`                  = '$hostname',
            `dhcp_vendor_class`         = '$dhcp_vendor_class',
            `dhcp_user_class`           = '$dhcp_user_class',
            `gateway_ip`                = if('$gateway_ip' = '0.0.0.0', `gateway_ip`, '$gateway_ip'),
            `dhcp_opt82_chasis_id`      = if('$dhcp_opt82_chasis_id' = '', `dhcp_opt82_chasis_id`, '$dhcp_opt82_chasis_id'),
            `dhcp_opt82_unit_id`        = if('$dhcp_opt82_unit_id' = '', `dhcp_opt82_unit_id`, '$dhcp_opt82_unit_id'),
            `dhcp_opt82_port_id`        = if('$dhcp_opt82_port_id' = '', `dhcp_opt82_port_id`, '$dhcp_opt82_port_id'),
            `dhcp_opt82_vlan_id`        = if('$dhcp_opt82_vlan_id' = '', `dhcp_opt82_vlan_id`, '$dhcp_opt82_vlan_id'),
            `dhcp_opt82_subscriber_id`  = if('$dhcp_opt82_subscriber_id' = '', `dhcp_opt82_subscriber_id`, '$dhcp_opt82_subscriber_id');
        "
    );
    $sth->execute();
    $sth->finish();
}
