 package Net::Shadowsocks::Server;

    # ABSTRACT: Shadowsocks protocol server module.
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
    use Net::Shadowsocks;
    use Net::Shadowsocks qw(_get_algorithm _get_mode _EVP_BytesToKey _initialize_cipher);
    use Socket qw(IPPROTO_TCP TCP_FASTOPEN SOL_SOCKET SO_REUSEPORT SO_REUSEADDR);

    our $VERSION = '0.8.1';
    
    $AnyEvent::Log::FILTER->level ("info");
    
    sub new($$$$)
     {
        my $_osname = $Config{osname};
        my $_osvers = $Config{osvers};
        AE::log info => "Shadowsocks remote server starting up on $_osname $_osvers";
        my ( $class, %args ) = @_;
        my $self = bless {
            map { ( $_ => $args{$_} ) }
              qw(password server server_port method),
        }, $class;
        if ( $self->{server} eq 'localhost' )
         {
            undef $self->{server};
        }

        my $tcp_server;
        $tcp_server = AnyEvent::Socket::tcp_server
        (
            $self->{server},
            $self->{server_port},
            sub {
                my ( $client_socket, $client_host, $client_port ) = @_;

                AE::log info => "Got new client connection: $client_host:$client_port";
                my $client_iv;
                my $mode = 0;

                my ( $encryptor, $decryptor, $key, $iv,$nonce ) = Net::Shadowsocks::_initialize_cipher( $self->{method},$self->{password} );
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
                        my $chandler = shift;
                        #AE::log info => "Client: Done.";
                        $chandler->destroy();
                    },
                    on_error => sub 
                    {
                        my ( $chandler, $fatal, $msg ) = @_;
                        AE::log error => $msg;
                        $chandler->destroy();
                    },
                    on_read => sub 
                    {
                        my $client_buffer = $clienthandler->rbuf();

                        if ( $client_buffer eq '' ) 
                        {
                            return;
                        }
                        else 
                        {
                            my $incomingdata = $client_buffer;
                            my $decrypteddata;
                            if ( !defined($client_iv) ) 
                            {
                                    $client_iv = substr( $client_buffer, 0, length($iv) );
                                    $incomingdata = substr( $client_buffer, length($iv) );

                                    if ( !defined($self->{method}) or $self->{method} eq 'rc4-md5' ) 
                                    {
                                        my $md = Digest::MD5->new();
                                        $md->add($key .$client_iv );
                                        #$md->add($client_iv);
                                        my $decrypt_rc4_key = $md->digest();
                                        Mcrypt::mcrypt_init($decryptor, $decrypt_rc4_key, '' );
                                    }
                                    elsif($self->{method} eq 'rc4-sha')
                                    {
                                        my $sha = Digest::SHA->new();
                                        $sha->add($key .$client_iv );
                                        #$md->add($client_iv);
                                        my $decrypt_rc4_key = substr($sha->digest(),0,16);
                                        Mcrypt::mcrypt_init($decryptor, $decrypt_rc4_key, '' );
                                    }
                                    elsif($self->{method} ne 'rc6' and $self->{method} ne 'chacha20-ietf' and  $self->{method} !~ /cfb$/ and $self-> {method} !~ /ctr$/ and $self->{method} !~ /^camellia/ )
                                    {
                                            Mcrypt::mcrypt_init($decryptor, $key, $client_iv );
                                    }
                                    else
                                    {
                                    
                                    }                                    
                                    if ($self->{method} eq 'rc6' or $self->{method} =~ /cfb$/ or $self->{method} =~ /ctr$/ or $self->{method} =~ /^camellia/)
                                    {
                                        $decrypteddata = $decryptor->decrypt($incomingdata,$key,$client_iv);
                                    }
                                    elsif($self->{method} eq 'chacha20-ietf')
                                    {
                                           #$decrypteddata = $decryptor->process($incomingdata);
                                       $decrypteddata = $decryptor->chacha20_ietf_xor($incomingdata,$client_iv,$key);
                                    }
                                    else 
                                    {
                                        $decrypteddata = Mcrypt::mcrypt_decrypt($decryptor, $incomingdata );
                                    }                                
                                    my $addrtype = ord( substr( $decrypteddata, 0, 1 ) );
                                    if (    $addrtype != 1 and $addrtype != 3 and $addrtype != 4 )
                                    {
                                        AE::log error => "Invalid address type";
                                        #return;
                                    }
                                    else
                                    {
                                        my $dest_addr;
                                        my $dest_port;

                                        if ( $addrtype == 1 ) 
                                        {
                                            if ( length($decrypteddata) >= 7 ) 
                                            {
                                                $dest_addr = format_address(substr( $decrypteddata, 1, 4 ) );
                                                $dest_port = unpack( ' n ',substr( $decrypteddata, 5, 2 ) );
                                                $decrypteddata = substr( $decrypteddata, 7 );
                                            }
                                            else 
                                            {
                                                return;
                                            }
                                        }
                                        elsif ( $addrtype == 3 ) 
                                        {
                                            if ( length($decrypteddata) > 2 ) 
                                            {
                                                my $addr_len = ord( substr( $decrypteddata, 1, 1 ) );
                                                if (length($decrypteddata) >= 4 + $addr_len )
                                                {
                                                    $dest_addr = substr( $decrypteddata, 2,$addr_len );
                                                    $dest_port = unpack('n',substr($decrypteddata,2 + $addr_len,2));
                                                    $decrypteddata = substr( $decrypteddata,4 + $addr_len );
                                                }
                                                else 
                                                {
                                                    return;
                                                }
                                            }
                                            else 
                                            {
                                                return;
                                            }
                                        }
                                        elsif ( $addrtype == 4 ) 
                                        {
                                            if ( length($decrypteddata) >= 19 ) 
                                            {
                                                $dest_addr = format_address(substr( $decrypteddata, 1, 16 ) );
                                                $dest_port = unpack( "n", substr( $decrypteddata, 17, 2 ) );
                                                $decrypteddata = substr( $decrypteddata, 19 );
                                            }
                                            else 
                                            {
                                                return;
                                            }
                                        }
=for comment
                                AnyEvent::Socket::resolve_sockaddr($dest_addr, $dest_port, "tcp", 0, undef, sub 
                                {
                                    my ( $ip_addr ) = @_;
                                    AE::log  info => "resolved " . AnyEvent::Socket::format_address( $ip_addr );
=cut
                                        $remotehandler = AnyEvent::Handle->new
                                        (
                                            autocork   => 1,
                                            keepalive  => 1,
                                            no_delay   => 1,
                                            connect    => [ $dest_addr, $dest_port ],
                                            on_connect => sub 
                                            {
                                                my ($rhandle,  $peerhost,$peerport, $retry) = @_;
                                                AE::log info => "Connected with $peerhost : $peerport."; 
                                            },
                                            on_connect_error => sub
                                            {
                                                my ($chandle,  $msg) = @_;
                                                AE::log error => $msg;
                                                $chandle->destroy();
                                                $mode = 0;
                                            },
                                            on_eof => sub 
                                            {
                                                my $rhandler = shift;
                                                #AE::log info => " Remote : Done . ";
                                                $rhandler->destroy();
                                                $mode = 0;
                                            },
                                            on_error => sub 
                                            {
                                                my ( $rhandler, $fatal, $msg ) = @_;
                                                AE::log error => $msg;
                                                $rhandler->destroy();
                                                $mode = 0;
                                            },
                                            on_prepare => sub
                                            {
                                                my $phandle = shift;
                                                setsockopt($phandle->{fh}, SOL_SOCKET, SO_REUSEPORT, 1);
                                            },
                                            on_read => sub 
                                            {
                                                my $remote_buffer = $remotehandler->rbuf();
                                                my $plaindata = $remote_buffer;
                                                my $encrypteddata;

                                                if ($self->{method} eq 'rc6' or $self->{method} =~ /cfb$/ or $self->{method} =~ /ctr$/ or $self->{method} =~ /^camellia/)
                                                {
                                                    $encrypteddata = $encryptor->encrypt($plaindata,$key,$iv); 
                                                }

                                                elsif($self->{method} eq 'chacha20-ietf')
                                                {
                                                        #$encrypteddata = $encryptor->process($plaindata);
                                                    $encrypteddata = $encryptor->chacha20_ietf_xor($plaindata,$iv,$key);
                                                }
                                                else 
                                                {
                                                    $encrypteddata = Mcrypt::mcrypt_encrypt($encryptor, $plaindata );
                                                }
                                        
                                                my $datatosend;
                                                if ( $mode == 0 ) 
                                                {
                                                    $datatosend = $iv . $encrypteddata;
                                                    $mode       = 1;
                                                }
                                                else 
                                                {
                                                    $datatosend = $encrypteddata;
                                                }
                                                $clienthandler->push_write($datatosend);
                                                $remotehandler->{rbuf} = '';
                                            }
                                       );
                                  }
#                                );
                            }
                            else 
                            {
                                if ( $self->{method} eq 'rc6'  or $self->{method} =~ /cfb$/ or $self->{method} =~ /ctr$/ or $self->{method} =~ /^camellia/) 
                                {
                                    $decrypteddata = $decryptor->decrypt($incomingdata,$key,$client_iv);
                                }

                                 elsif($self->{method} eq 'chacha20-ietf')
                                       {
                                           #$decrypteddata = $decryptor->process($incomingdata);
                                            $decrypteddata = $decryptor->chacha20_ietf_xor($incomingdata,$client_iv,$key);
                                       }
                                else 
                                {
                                    $decrypteddata = Mcrypt::mcrypt_decrypt($decryptor, $incomingdata );
                                }
                            }
                            $remotehandler->push_write($decrypteddata);
                            $clienthandler->{rbuf} = '';
                        }
                    }
                );
            },
            sub 
            {
                my $client_socket = shift;
                setsockopt($client_socket,,SOL_SOCKET, SO_REUSEADDR, 1);
                if ( $_osname eq 'linux' ) 
                {
                    my $_tfo = do 
                    {
                        local ( @ARGV, $/ ) = '/proc/sys/net/ipv4/tcp_fastopen';<>;
                    };
                    if ( $_tfo == 2 or $_tfo == 3 ) 
                    {
                        setsockopt( $client_socket, IPPROTO_TCP, TCP_FASTOPEN, 1 );
                        AE::log info => "TCP Fast Open enabled on server.";
                    }
                }
                elsif ( $_osname eq 'darwin' ) 
                {
                    my $_version_major = substr( $_osvers, 0, index( $_osvers, '.' ) );
                    if ( $_version_major >= 15 ) 
                    {
                        setsockopt( $client_socket, IPPROTO_TCP, TCP_FASTOPEN, 1 );
                        AE::log info => "TCP Fast Open enabled on server.";
                    }
                }
            },
        );
        my $cv = AE::cv;
        $cv->recv();
        return $self;
    }
    1;    # End of Net::Shadowsocks::Server
  
  __END__ 
    
=pod

=encoding utf8
    
=head1 NAME

Net::Shadowsocks::Server

=head1 VERSION

Version 0.8.1

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

    The C<new> constructor lets you create a new B<Net::Shadowsocks::Server> object.

    So no big surprises there...

    Returns a new B<Net::Shadowsocks::Server> or dies on error.

    example use:

    use Net::Shadowsocks::Server;

    my $foo = Net::Shadowsocks::Server->new(
    password => ' 49923641 ',
    server => ' jp . ssip . club ',
    server_port => 23333,
    method => 'rc6',
    );

    This is all you need to do. Take a look at server.pl under eg directory for a compelete example on how to
    use the server module.

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

