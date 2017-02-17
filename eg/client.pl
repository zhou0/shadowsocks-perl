#!/usr/bin/perl
# Modify the config.json.sample file, save it to config.json. Run server.pl on
# server, run client.pl on localhost. Config your browser to use socks 5 proxy
# with remote DNS support and you can now break through the great firewall of
# china.

use 5.006;
use strict;
use warnings;
use Getopt::Long;
use JSON;
use Net::Shadowsocks::Client;
use Term::ANSIColor;

sub print_help {
   print("Usage: vmcomlite.pl [-a] [-h] [-g]\n\n");
   print("-a FILE, --analyse=FILE\t\tAnalyse FILE\n");
   print("-ho PW, --hostpass=PW\t\tUse PW as password to the host OS\n");
   print("-g PW, --guestpass=PW\t\tUse PW as password to the virtual machine's OS\n");
   print("-t, --takesnapshot\t\tTake a snapshot of the virtual machine's state\n");
   print("\t\t\t\t(maximum one snapshot can be stored per virtual\n");
   print("\t\t\t\tmachine for VMware Server)\n");
   print("-he, --help\t\t\tThis help screen\n");
   die "\n"; 
}

local $/;
open(my $fh, '<', 'config.json') or die "Can't open  config.json: $!";
my $confg_json = <$fh>;
close($fh) || warn "close failed: $!";
my $config    = decode_json($confg_json);
my $_tcp_host = $config->{'local_address'};

my $_tcp_service   = $config->{'local_port'};
my $_password      = $config->{'password'};
my $_remotehost    = $config->{'server'};
my $_remoteservice = $config->{'server_port'};
my $_method = $config->{'method'};

my $foo = Net::Shadowsocks::Client->new(
                                local_address => $_tcp_host,
                                local_port    => $_tcp_service,
                                password      => $_password,
                                server        => $_remotehost,
                                server_port   => $_remoteservice,
                                method => $_method
                               );

