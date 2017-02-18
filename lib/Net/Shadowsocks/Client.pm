package Net::Shadowsocks::Client;

    # ABSTRACT: Shadowsocks protocol client module.
    # KEYWORDS: socks shadowsocks rfc1928 Great Firewall Internet censorship in China
    use 5.006;
    use strict;
    use warnings;
    use AnyEvent;
    use AnyEvent::Handle;
    use AnyEvent::Log;
    use AnyEvent::Socket;
    use Carp;
    use Config;
    use Digest::MD5;
    use Digest::SHA;
    use IO::Socket::Socks qw(:constants $SOCKS_ERROR ESOCKSPROTO);
    use Net::Shadowsocks;
    use Net::Shadowsocks qw( _get_algorithm _get_mode _EVP_BytesToKey _initialize_cipher);
    use Socket qw(IPPROTO_TCP MSG_FASTOPEN SOL_SOCKET SO_REUSEPORT SO_REUSEADDR);

    our $VERSION = '0.8.2';
    $AnyEvent::Log::FILTER->level ("info");
    sub new($$$$$$) 
    {
        my $_osname = $Config{osname};
        my $_osvers = $Config{osvers};
        AE::log info => "Shadowsocks local server starting up on $_osname $_osvers";
        my ( $class, %args ) = @_;
        my $self = bless {
            map { ( $_ => $args{$_} ) }
              qw(local_address local_port password server server_port method),
        }, $class;
        if (defined($self->{local_address}))
        {
             if( $self->{local_address} eq 'localhost' ) 
            {
            undef $self->{local_address};
            }
        }

        my $tcp_server;
        $tcp_server = AnyEvent::Socket::tcp_server(
            $self->{local_address},
            $self->{local_port},
            sub 
            {
                my ( $client_socket, $client_host, $client_port ) = @_;

                AE::log info => "Got new client connection: $client_host:$client_port";
                my $addr_to_send = '';
                my $server_iv;
                my $server_nonce;
                my $stage = 0;
                my $mode  = 0;
                my ( $encryptor, $decryptor, $key, $iv, $nonce ) = Net::Shadowsocks::_initialize_cipher( $self->{method},$self->{password} );
                my $clienthandler;
                my $remotehandler;
                $clienthandler = AnyEvent::Handle->new
                (
                    autocork  => 1,
                    keepalive => 1,
                    no_delay  => 1,
                    fh        => $client_socket,
                    on_eof    => sub 
                    {
                        my $chandle = shift;
                        #AE::log info => "Client: Done.";
                        $chandle->destroy();
                    },
                    on_error => sub 
                    {
                        my ( $chandle, $fatal, $msg ) = @_;
                        AE::log error => $msg;
                        $chandle->destroy();
                    },
                    on_read => sub 
                    {
                        my $chandle = shift;
                        my $client_buffer = $clienthandler->rbuf();

                        if ( $client_buffer eq '' ) 
                        {
                            return;
                        }
                        else 
                        {
                            if ( $stage == 0 ) 
                            {
                                my $ver = ord( substr( $client_buffer, 0, 1 ) );

                                if ( $ver != SOCKS5_VER )
                                 {
                                     AE::log error => "Socks version should be 5, $ver recieved";
                                     $chandle->destroy();
                                    #return;
                                }
                                else
                                {
                                    my $nmethods = ord( substr( $client_buffer, 1, 1 ) );

                                    if ( $nmethods == 0 ) 
                                    {
                                        AE::log error =>  "No authentication methods sent" ;
                                        $chandle->destroy();
                                        #return;
                                    }
                                    else
                                    {
                                        my @methods = unpack( 'C' x $nmethods, substr( $client_buffer, 2 ) );

                                        $clienthandler->push_write(pack( 'CC', SOCKS5_VER, 0 ) );
                                        $stage = 1;
                                    }
                                }
                            }
                            elsif ( $stage == 1 ) 
                            {
                                my $cmd = ord( substr( $client_buffer, 1, 1 ) );

                                if ( $cmd == CMD_CONNECT ) 
                                {
                                    my $addrtype = ord( substr( $client_buffer, 3, 1 ) );
                                    if (    $addrtype != 1 and $addrtype != 3 and $addrtype != 4 )
                                    {
                                          AE::log error => "'Invaliad address type'";
                                          $chandle->destroy();
                                        #return;
                                    }
                                    else
                                    {
                                        $addr_to_send = substr( $client_buffer, 3 );
                                        if ( !defined( $self->{local_address} ) ) 
                                        {
                                             $self->{local_address} = 'localhost';
                                        }
                                        my $hlen = length( $self->{local_address} );
                                        $clienthandler->push_write(pack( 'CCCC',SOCKS5_VER, 0,0,          ADDR_DOMAINNAME )
                                          . pack( 'C', $hlen )
                                          . $self->{local_address}
                                          . pack( 'n', $self->{local_port} )
                                        );
                                        $stage = 4;

                                        $remotehandler = AnyEvent::Handle->new
                                        (
                                            autocork  => 1,
                                            keepalive => 1,
                                            no_delay  => 1,
                                            connect   => [$self->{server},$self->{server_port}],
                                            on_connect => sub 
                                            {
                                                $stage = 5;
                                            },
                                            on_connect_error => sub
                                            {
                                                 my ($chandle,  $msg) = @_;
                                                    AE::log error => $msg;
                                                    $chandle->destroy();
                                                    $mode = 0;
                                                    #return;
                                            },
                                            on_eof => sub 
                                            {
                                                 my $rhandle = shift;
                                                #AE::log info => "Remote: Done.";
                                                $rhandle->destroy();
                                                $mode = 0;
                                            },
                                            on_error => sub 
                                            {
                                                my ( $rhandle, $fatal, $msg ) = @_;
                                                AE::log error => $msg;
                                                $rhandle->destroy();
                                                $mode = 0;
                                            },
                                            on_prepare => sub
                                            {
                                                my $phandle = shift;
                                                setsockopt($phandle->{fh}, SOL_SOCKET, SO_REUSEPORT, 1);
                                            },
                                            on_read => sub 
                                            {
                                                my $incomingdata = $remotehandler->rbuf();
                                                my $decrypteddata;
                                                unless ( defined($server_iv) ) 
                                                {
                                                    $server_iv = substr( $incomingdata, 0,length($iv) );
                                                    $incomingdata = substr($incomingdata,length($iv));
                                                    if ( !defined($self->{method}) or $self->{method} eq'rc4-md5' )
                                                    {
                                                        my $md = Digest::MD5->new();
                                                        $md->add($key . $server_iv);
                                                        #$md->add($server_iv);
                                                        my $decrypt_rc4_key = $md->digest();
                                                        Mcrypt::mcrypt_init($decryptor,$decrypt_rc4_key,'' );
                                                    }
                                                    elsif($self->{method} eq'rc4-sha')
                                                    {
                                                        my $sha = Digest::SHA->new();
                                                        $sha->add($key . $server_iv);
                                                        #$md->add($server_iv);
                                                        my $decrypt_rc4_key = substr($sha->digest(),0,16);
                                                        Mcrypt::mcrypt_init($decryptor,$decrypt_rc4_key,'' );
                                                    }
=for comment
                                                            elsif($self->{method} =~ /ctr$/)
                                                            {
                                                                $decryptor =   Crypt::Nettle::Cipher->new('decrypt', Net::Shadowsocks::_get_algorithm($self->{method}), $key, Net::Shadowsocks::_get_mode($self->{method}) ,$server_iv);                                                                
                                                                }
=cut
                                                    elsif($self->{method} ne'rc6' and $self->{method} ne 'chacha20-ietf' and $self->{method} !~ /cfb$/ and $self->{method} !~ /ctr$/  and $self->{method} !~ /^camellia/ )
                                                    {
                                                            Mcrypt::mcrypt_init($decryptor,$key,$server_iv );
                                                    }
                                                }
                                                if ($self->{method} eq 'rc6' or $self->{method} =~ /cfb$/ or $self->{method} =~ /ctr$/ or $self->{method} =~ /^camellia/)
                                                {
                                                    $decrypteddata = $decryptor->decrypt($incomingdata,$key,$server_iv);
                                                }

                                                elsif($self->{method} eq 'chacha20-ietf')
                                                {
                                                    $decrypteddata = $decryptor->chacha20_ietf_xor($incomingdata,$server_iv,$key);
                                                }

                                                else
                                                {
                                                    $decrypteddata = Mcrypt::mcrypt_decrypt($decryptor, $incomingdata );
                                                }
                                                $clienthandler->push_write($decrypteddata);
                                                $remotehandler->{rbuf} = '';
                                             },
                                         );
                                    }
                                }
                                elsif ( $cmd == CMD_BIND ) 
                                {
                                    carp 'BIND Request not supported';
                                    $stage = 0;
                                    $clienthandler->destroy();
                                    #return;
                                }
                                elsif ( $cmd == CMD_UDPASSOC ) 
                                {
                                    carp 'UDP ASSOCIATE request not implemented';
                                    $stage = 0;
                                    $clienthandler->destroy();
                                    #return;
                                }

                                else 
                                {
                                    carp 'Unknown command';
                                    $stage = 0;
                                    $clienthandler->destroy();
                                    #return;
                                }
                            }

                            elsif ( $stage == 4 or $stage == 5 ) 
                            {
                                my $plaindata = $client_buffer;
                                my $encrypteddata;
                                if ( $addr_to_send ne '' ) 
                                {
                                    $plaindata = $addr_to_send . $client_buffer;
                                    $addr_to_send = '';
                                }
                                if ( $self->{method} eq 'rc6' or $self->{method} =~ /cfb$/ or $self->{method} =~ /ctr$/ or $self->{method} =~ /^camellia/) 
                                {                                
                                    $encrypteddata = $encryptor->encrypt($plaindata,$key,$iv);
                                }
                                elsif($self->{method} eq 'chacha20-ietf')
                                {
                                     $encrypteddata = $encryptor->chacha20_ietf_xor($plaindata,$nonce,$key);
                                }
                                else
                                {
                                     $encrypteddata = Mcrypt::mcrypt_encrypt($encryptor,$plaindata);
                                }
                                
                                my $datatosend;
                                if ( $mode == 0  ) 
                                {
                                    if (   $self->{method} =~ /gcm$/ or $self->{method} =~ /poly1305$/ )
                                    {
                                        $datatosend = $nonce . $encrypteddata;
                                    }
                                    else {
                                        $datatosend = $iv . $encrypteddata;
                                    }
                                    $mode = 1;
                                }
                                else 
                                {
                                    $datatosend = $encrypteddata;
                                }

                                $remotehandler->push_write($datatosend);
                            }
                        }
                        $clienthandler->{rbuf} = '';
                    },
                );
            },
            sub
            {
                my ($fh) = shift;
                setsockopt($fh, SOL_SOCKET, SO_REUSEADDR, 1);
            }
        );
        my $cv = AE::cv;
        $cv->recv();
        return $self;
    }
    1;    # End of Net::Shadowsocks::Client
 
  __END__
    
=pod

=encoding utf8

=head1 NAME

Net::Shadowsocks::Client

=head1 VERSION

Version 0.8.2

=head1 SYNOPSIS

    Shadowsocks protocol server module.
    
=head1 DESCRIPTION

1. A total of 28 encryption methods are supported:

AES-128-CBC AES-128-CFB AES-128-CTR AES-128-OFB 
AES-192-CBC AES-192-CFB AES-192-CTR AES-192-OFB 
AES-256-CBC AES-256-CFB AES-256-CTR AES-256-OFB
Camellia-128-CBC Camellia-128-CFB Camellia-128-CTR Camellia-128-OFB 
Camellia-192-CBC Camellia-192-CFB Camellia-192-CTR Camellia-192-OFB 
Camellia-256-CBC Camellia-256-CFB Camellia-256-CTR Camellia-256-OFB
Chacha20-IETF
RC4-MD5 RC4-SHA RC6 

2.The following ciphers deprecated by Shadowsocks are not supported: 
bf-cfb chacha20 salsa20

3.The following ciphers recommended by Shadowsocks are not supported yet: 
aes-128-gcm aes-192-gcm aes-256-gcm 
chacha20-ietf-poly1305 
xchacha20-ietf-poly1305 

Please note TLS 1.2 has removed IDEA and DES cipher suites. and because of 
CVE-2016-2183,  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183
, this module has removed all support for DES and 3DES ciphers.

Project website https://osdn.net/projects/ssperl/

=head1 METHODS

=head2 new

    The C<new> constructor lets you create a new B<Net::Shadowsocks::Client> object.

    So no big surprises there...

    Returns a new B<Net::Shadowsocks::Client> or dies on error.

    example use:

    use Net::Shadowsocks::Client;

    my $foo = Net::Shadowsocks::Client->new(
    local_address => 'localhost',
    local_port => 1491,
    password => '49923641',
    server => 'jp.ssip.club',
    server_port => 23333,
    method => 'rc6',
    );

    This is all you need to do. Take a look at client.pl under eg directory for a compelete example on how to
    use the client module.

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