#!/usr/bin/env perl
# ABSTRACT: the asynchronous, non-blocking shadowsocks client and server. 
# KEYWORDS: socks shadowsocks rfc1928 Great Firewall Internet censorship in China
#
# Modify the config.json sample, save it to config.json. Run ssserver.pl on
# server, run ssclient.pl on localhost. Config your browser to use socks 5 proxy
# with remote DNS support and you can now break through the great firewall of
# china.

use 5.006;
use strict;
use warnings;
use Getopt::Std;
use JSON;
use Net::Shadowsocks::Client;

my $version = "0.9.3.3";

sub main::HELP_MESSAGE()
{
    print("Usage: ssclient.pl -s SERVER_ADDR -p SERVER_PORT [-b LOCAL_ADDR]
    -l LOCAL_PORT -k PASSWORD -m METHOD [-c CONFIG]\n\n");
    printf("\tPleae note that all optional arguments must be in lower case.\n\n");
    print("\t-s SERVER_ADDR\t\tYour server host name or ip address\n");
    print("\t-p SERVER_PORT\t\tYour server port\n");
    print("\t-b LOCAL_ADDR\t\tYour client host name or ip address\n");
    print("\t-l LOCAL_PORT\t\tYour browser`s socks5 proxy port\n");
    print("\t-k PASSWORD\t\tYour top-secret password\n");
    print("\t-m METHOD\t\tYour favarite encryption method, pick one of the methods below:\n");
    print("\taes-128-cfb aes-128-ctr aes-128-gcm aes-128-ofb\n");
    print("\taes-192-cfb aes-192-ctr aes-192-gcm aes-192-ofb\n");
    print("\taes-256-cfb aes-256-ctr aes-256-gcm aes-256-ofb\n");
    print("\tcamellia-128-cfb camellia-128-ctr camellia-128-ofb\n");
    print("\tcamellia-192-cfb camellia-192-ctr camellia-192-ofb\n");
    print("\tcamellia-256-cfb camellia-256-ctr camellia-256-ofb\n");
    if ($^O ne "MSWin32")
    {
        print("\tchacha20-ietf chacha20-ietf-poly1305\n");
    }
#    print("\trabbit\n");
    print("\trc4-md5\n");
    print("\trc6-128-cfb rc6-128-ctr rc6-128-ofb\n");
    print("\trc6-192-cfb rc6-192-ctr rc6-192-ofb\n");
    print("\trc6-256-cfb rc6-256-ctr rc6-256-ofb\n");
    print("\tspritz\n");
    printf("\t-c CONFIG\t\tFull path of your config.json file\n");
    print("\t-h, --help\t\tDisplay this help screen\n");
    print("\t-v, --version\t\tDisplay version information\n");
    die "\n";
}

sub main::VERSION_MESSAGE()
{
    print "Net::Shadowsocks::Client version $version\n";
}

$Getopt::Std::STANDARD_HELP_VERSION = 1;
main::HELP_MESSAGE() unless ($ARGV[0]);

my %options=();
getopts('hb:c:k:l:m:p:s:v',\%options);

if (defined($options{h}))
{
    main::HELP_MESSAGE();
}
elsif(defined($options{v}))
{
    main::VERSION_MESSAGE();
}
else
{
    if (!defined($options{k}) or !defined($options{l}) or !defined($options{p}) or !defined($options{s}) )
    {
        if(!defined($options{c}))
        {
            print"You did not provide server, server port, local port or password command argument or any configuration file, try again .\n";
            main::HELP_MESSAGE();
        }
        else
        {
            local $/;
            open(my $fh, '<', $options{c}) or die "Can't open  config.json: $!";
            my $confg_json = <$fh>;
            close($fh) || warn "close failed: $!";
            my $config    = decode_json($confg_json);
            $options{b}      = $config->{'local_address'};
            $options{l}  = $config->{'local_port'};
            $options{k}      = $config->{'password'};
            $options{s}  = $config->{'server'};
            $options{p} = $config->{'server_port'};
            $options{m} = $config->{'method'};
        }
    }

    my $foo = Net::Shadowsocks::Client->new(
    local_address =>$options{b},
    local_port  => $options{l},
    password    => $options{k},
    server    => $options{s},
    server_port   => $options{p},
    method => $options{m}
    );
}

=pod

=encoding utf8

=head1 NAME

ssclient.pl

=head1 VERSION

Version 0.9.3.3

=head1 SYNOPSIS

Usage: ssclient.pl -s SERVER_ADDR -p SERVER_PORT [-b LOCAL_ADDR]
    -l LOCAL_PORT -k PASSWORD -m METHOD [-c CONFIG]

	Pleae note that all optional arguments must be in lower case.

	-s SERVER_ADDR		Your server host name or ip address
	-p SERVER_PORT		Your server port
	-b LOCAL_ADDR		Your client host name or ip address
	-l LOCAL_PORT		Your browser`s socks5 proxy port
	-k PASSWORD		Your top-secret password
	-m METHOD		Your favarite encryption method, pick one of the methods below:
	aes-128-cfb aes-128-ctr aes-128-gcm aes-128-ofb
	aes-192-cfb aes-192-ctr aes-192-gcm aes-192-ofb
	aes-256-cfb aes-256-ctr aes-256-gcm aes-256-ofb
	camellia-128-cfb camellia-128-ctr camellia-128-ofb
	camellia-192-cfb camellia-192-ctr camellia-192-ofb
	camellia-256-cfb camellia-256-ctr camellia-256-ofb
	chacha20-ietf chacha20-ietf-poly1305
	rc6-128-cfb rc6-128-ctr rc6-128-ofb
	rc6-192-cfb rc6-192-ctr rc6-192-ofb
	rc6-256-cfb rc6-256-ctr rc6-256-ofb
	spritz
	-c CONFIG		Full path of your config.json file
	-h, --help		Display this help screen
	-v, --version		Display version information


=head1 DESCRIPTION

Shadowsocks protocol client.

=head1 SEE ALSO

L<Shadowsocks Official website |https://shadowsocks.org/en/index.html>,L<Shadowsocks on Wikipedia |https://en.wikipedia.org/wiki/Shadowsocks>


Net::Shadowsocks is a Perl implementation of the shadowsocks (Chinese: 影梭)
protocol client and server , Shadowsocks is a secure transport protocol based on
SOCKS Protocol Version 5 (RFC 1928 ).

1. A total of 34 encryption methods are supported:

        aes-128-cfb aes-128-ctr aes-128-gcm aes-128-ofb
	aes-192-cfb aes-192-ctr aes-192-gcm aes-192-ofb
	aes-256-cfb aes-256-ctr aes-256-gcm aes-256-ofb
	camellia-128-cfb camellia-128-ctr camellia-128-ofb
	camellia-192-cfb camellia-192-ctr camellia-192-ofb
	camellia-256-cfb camellia-256-ctr camellia-256-ofb
	chacha20-ietf chacha20-ietf-poly1305
	rc6-128-cfb rc6-128-ctr rc6-128-ofb
	rc6-192-cfb rc6-192-ctr rc6-192-ofb
	rc6-256-cfb rc6-256-ctr rc6-256-ofb
	spritz

2.The following ciphers deprecated by Shadowsocks are not supported:

        bf-cfb chacha20 salsa20 

3.The following ciphers recommended by Shadowsocks are not supported yet:

        xchacha20-ietf-poly1305

Please note TLS 1.2 has removed IDEA and DES cipher suites. and because of
CVE-2016-2183,  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183
, this module has removed all support for DES and 3DES ciphers.

Project website https://osdn.net/projects/ssperl/

=head1 AUTHOR

Li ZHOU, C<< <lzh at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-shadowsocks at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Shadowsocks>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

perldoc Net::Shadowsocks


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Shadowsocks>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-Shadowsocks>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-Shadowsocks>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-Shadowsocks/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2017 Li ZHOU.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS " AS IS ' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut
