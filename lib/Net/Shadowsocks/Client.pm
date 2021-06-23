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
    use Crypt::KeyDerivation qw(hkdf);
    BEGIN 
    {
       my $_win32 = ($^O eq "MSWin32") ? 1 : 0;                 
       if ($_win32) 
       {
       }
       else 
       {
           eval "use Crypt::NaCl::Sodium qw( :utils )";
           die "$@" if $@;
       }
    }
    use Digest::MD5;
    #use Digest::SHA;
    use IO::Socket::Socks qw(:constants);
    use Net::Shadowsocks;
    use Net::Shadowsocks qw( _get_algorithm _get_mode _get_iv_size _EVP_BytesToKey _initialize_cipher);
    use Socket qw(IPPROTO_TCP MSG_FASTOPEN SOL_SOCKET SO_REUSEPORT SO_REUSEADDR);
    #use String::HexConvert ':all';
    
    our $VERSION = '0.9.3.4';
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
        unless (defined($self->{method}))
        {
            $self->{method} = 'spritz';
        } 

        my $tcp_server;
        $tcp_server = AnyEvent::Socket::tcp_server(
            $self->{local_address},
            $self->{local_port},
            sub 
            {
                my ( $client_socket, $client_host, $client_port ) = @_;

                #AE::log info => "Got new client connection: $client_host:$client_port";
                my $addr_to_send = undef;
                my $server_iv;
                my $decrypt_subkey;
                my $stage = 0;
                my $mode  = 0;
                my ( $encryptor, $decryptor, $key, $encrypt_subkey,$iv, $encrypt_nonce,$decrypt_nonce ) = Net::Shadowsocks::_initialize_cipher( $self->{method},$self->{password} );
                my $clienthandler;
                my $remotehandler;
                my $encrypt_counter = 0;
                my $decrypt_counter = 0;
                $clienthandler = AnyEvent::Handle->new
                (
                    autocork  => 1,
                    keepalive => 1,
                    no_delay  => 1,
                    fh        => $client_socket,
                    on_eof    => sub 
                    {
                        my $chandle = shift;
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
                        my $client_buffer = $chandle->rbuf();

                        if ( length($client_buffer)  == 0 ) 
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

                                        $chandle->push_write(pack( 'CC', SOCKS5_VER, 0 ) );
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
                                                if ($^O eq "MSWin32")
                                                {
                                                     setsockopt($phandle->{fh}, SOL_SOCKET, SO_REUSEADDR, 1);
                                                }
                                                else
                                                {
                                                    setsockopt($phandle->{fh}, SOL_SOCKET, SO_REUSEADDR, 1);
                                                    setsockopt($phandle->{fh}, SOL_SOCKET, SO_REUSEPORT, 1);
                                                }
                                            },
                                            on_read => sub 
                                            {
                                                my $rhandle = shift;
                                                my $incoming_data = $rhandle->rbuf();
                                                #my $decrypted_data = undef;
                                                my $decrypted_data = "";
                                                unless ( defined($server_iv) ) 
                                                {
                                                    if (length($incoming_data) < length($iv))
                                                    {
                                                        return;
                                                    }
                                                    else
                                                    {
                                                        $server_iv = substr( $incoming_data, 0,length($iv) );
                                                        $incoming_data = substr($incoming_data,length($iv));
                                                        $rhandle->{rbuf} = $incoming_data;
                                                        
                                                        if ( $self->{method} eq'rc4-md5' )
                                                        {
                                                            my $md = Digest::MD5->new();
                                                            $md->add($key . $server_iv);
                                                            #$md->add($server_iv);
                                                            my $decrypt_rc4_key = $md->digest();
                                                            $decryptor = Crypt::RC4::XS->new($decrypt_rc4_key);
                                                        }
                                                        
                                                        elsif ( !defined($self->{method}) or $self->{method} eq'spritz' )
                                                        {
                                                           
                                                            $decryptor = Crypt::Spritz::Cipher->new($key,$server_iv);
                                                        } 
                                                        elsif ( $self->{method} eq'rabbit' )
                                                        {
                                                            my $md = Digest::MD5->new();
                                                            $md->add($key . $server_iv);
                                                            #$md->add($server_iv);
                                                            my $decrypt_rabbit_key = $md->digest();
                                                            $decryptor = Crypt::Rabbit->new($decrypt_rabbit_key);
                                                        }   
                                                        elsif($self->{method} =~ /gcm$/ or $self->{method} =~ /poly1305$/)
                                                        {
                                                          $decrypt_subkey = hkdf($key,$server_iv,'SHA1',Net::Shadowsocks::_get_key_size($self->{method}),"ss-subkey");
                                                          #carp ascii_to_hex($decrypt_subkey);
                                                          if($self->{method} =~ /gcm$/ )
                                                          {
                                                              $decryptor = Crypt::AuthEnc::GCM->new('AES', $decrypt_subkey);
                                                          }
                                                        }
                                                    }    
                                                }
                                                if (length($incoming_data) == 0)
                                                {
                                                    return;
                                                }
                                                else
                                                {

                                                    if (  $self->{method} eq 'rc4-md5')
                                                    {
                                                        $decrypted_data = $decryptor->RC4($incoming_data );
                                                    }

                                                    elsif (  $self->{method} eq "rabbit" or $self->{method} eq "spritz")
                                                    {
                                                        $decrypted_data = $decryptor->decrypt($incoming_data);
                                                    }
                                                    elsif($self->{method} =~ /^chacha20/)
                                                    {
                                                        if ($self->{method} eq 'chacha20-ietf')
                                                        {
                                                            #my $ct_len = length($incoming_data)  % 64;
                                                            my $pad_len = $decrypt_counter % 64 ;
                                                            my $padded_incoming_data  = Net::Shadowsocks::_add_padding($incoming_data,$pad_len); 
                                                            my $padded_decrypted_data = $decryptor->chacha20_ietf_xor_ic($padded_incoming_data,$server_iv,$decrypt_counter / 64 ,$key);
                                                            #$decrypted_data = $decryptor->chacha20_ietf_xor_ic($incoming_data,$server_iv,$decrypt_counter / 64 ,$key);
                                                            $decrypted_data = Net::Shadowsocks::_remove_padding($padded_decrypted_data,$pad_len);
                                                            #$decrypted_data = $decryptor->chacha20_ietf_xor($incoming_data,$server_iv ,$key);
                                                            $decrypt_counter +=  length($incoming_data);
                                                        }
                                                        else
                                                        {
                                                            #my $data_len_total = 0;
                                                            while (length($incoming_data) > 0)
                                                            {
                                                                #carp length($incoming_data) . " bytes received";
                                                                if (length($incoming_data) < 34)
                                                                {
                                                                    return;
                                                                }
                                                                else
                                                                {
                                                                    my $data_len_ct = substr($incoming_data,0,18); 
                                                                    my $data_len_pt;
                                                                    eval
                                                                    {
                                                                        $data_len_pt = $decryptor->ietf_decrypt($data_len_ct, "", $decrypt_nonce, $decrypt_subkey);
                                                                    };
                                                                    if ( $@ ) 
                                                                    {
                                                                        AE::log error =>  "data length forged!";
                                                                        $rhandle->destroy();
                                                                    } 
                                                                    else 
                                                                    {
                                                                        #$decrypt_nonce = $decrypt_nonce->increment();
                                                                        my $data_len = unpack('n',$data_len_pt); 
                                                                        #carp "Decrypted data length: $data_len";
                                                                        my $chunk_len = $data_len + 34;
                                                                    
                                                                        #$data_len_total += $data_len;
                                                                        if (length($incoming_data) < $chunk_len)
                                                                        {
                                                                            return;
                                                                        }
                                                                        else
                                                                        {
                                                                            $decrypt_nonce = $decrypt_nonce->increment();
                                                                            $decrypted_data .= $decryptor->ietf_decrypt(substr($incoming_data,18,$data_len + 16),"",$decrypt_nonce,$decrypt_subkey);
                                                                            if ( $@ ) 
                                                                            {
                                                                                AE::log error =>  "data forged!";
                                                                                $rhandle->destroy();
                                                                            }
                                                                            else
                                                                            {
                                                                                $decrypt_nonce = $decrypt_nonce->increment(); 
                                                                                $incoming_data = substr($incoming_data,$chunk_len);                                                                       
                                                                                $rhandle->{rbuf} = $incoming_data;
                                                                                #carp length($incoming_data);
                                                                            }  
                                                                        }      
                                                                    }
                                                                }
                                                            }
                                                            #carp $data_len_total;
                                                            #carp length($decrypted_data);
                                                        }
                                                    }
                                                    elsif($self->{method} =~ /gcm$/)
                                                    {
                                                        #my $chunk_len = 0;
                                                        while (length($incoming_data) > 0)
                                                        {
                                                            if (length($incoming_data) < 34)
                                                            {
                                                                return;
                                                            }
                                                            else
                                                            {
                                                                my $data_len_ct = substr($incoming_data,0,2); 
                                                                $decryptor->reset();
                                                                $decryptor->iv_add($decrypt_nonce);
                                                                $decryptor->adata_add("");
                                                                my $data_len_pt = $decryptor->decrypt_add($data_len_ct);
                                                                my $data_len_tag = substr($incoming_data,2,16);
                                                                my $length_result = $decryptor->decrypt_done($data_len_tag);
                                                                if (!$length_result)
                                                                {
                                                                    AE::log error =>  "data length forged!";
                                                                    $rhandle->destroy();
                                                                } 
                                                                else 
                                                                {
                                                                    my $data_len = unpack('n',$data_len_pt); 
                                                                    #carp "Decrypted data length: $data_len\n";
                                                                    my $chunk_len = $data_len + 34;
                                                                    if (length($incoming_data) < $chunk_len)
                                                                    {
                                                                        return;
                                                                    }
                                                                    else
                                                                    {
                                                                        $decrypt_nonce = $decrypt_nonce->increment();
                                                                        $decryptor->reset();
                                                                        $decryptor->iv_add($decrypt_nonce);
                                                                        $decryptor->adata_add("");
                                                                        $decrypted_data .= $decryptor->decrypt_add(substr($incoming_data,18,$data_len ));
                                                                        my $data_tag = substr($incoming_data,18 + $data_len,16);
                                                                        my $data_result = $decryptor->decrypt_done($data_tag);
                                                                        if ( !$data_result ) 
                                                                        {
                                                                            AE::log error =>  "data forged!";
                                                                            $rhandle->destroy();
                                                                        }
                                                                        else
                                                                        {
                                                                            $decrypt_nonce = $decrypt_nonce->increment();  
                                                                            #$decryptor->reset();    
                                                                            #$decryptor->iv_add($decrypt_nonce);
                                                                            #$decryptor->adata_add(""); 
                                                                            $incoming_data = substr($incoming_data,$chunk_len);                                                                       
                                                                            $rhandle->{rbuf} = $incoming_data;     
                                                                            #carp "more chunk to process" if (length($incoming_data ) > 0);                                                                                                      
                                                                        }  
                                                                    }      
                                                                }
                                                            }
                                                        }
                                                    }                                              
                                                    else
                                                    {
                                                        $decrypted_data = $decryptor->decrypt($incoming_data,$key,$server_iv);
                                                    }
                                                    $chandle->push_write($decrypted_data);
                                                    if ($self->{method} !~ /gcm$/ and $self->{method} !~ /poly1305$/)
                                                    {
                                                        $rhandle->{rbuf} = undef;
                                                    }
                                                 }
                                             }
                                         );
                                    }                                   
                                }
                                elsif ( $cmd == CMD_BIND ) 
                                {
                                    carp 'BIND Request not supported';
                                    $stage = 0;
                                    $chandle->destroy();
                                    #return;
                                }
                                elsif ( $cmd == CMD_UDPASSOC ) 
                                {
                                    carp 'UDP ASSOCIATE request not implemented';
                                    $stage = 0;
                                    $chandle->destroy();
                                    #return;
                                }

                                else 
                                {
                                    carp 'Unknown command';
                                    $stage = 0;
                                    $chandle->destroy();
                                    #return;
                                }
                            }

                            elsif ( $stage == 4 or $stage == 5 ) 
                            {
                                my $plain_data = $client_buffer;
                                my $encrypted_data;
                                if ( defined($addr_to_send )) 
                                {
                                    $plain_data = $addr_to_send . $client_buffer;
                                    $addr_to_send = undef;
                                }

                                if ( $self->{method} eq 'rc4-md5'  ) 
                                {
                                    $encrypted_data = $encryptor->RC4($plain_data);                                
                                }
                                elsif ( $self->{method} eq "rabbit" or $self->{method} eq "spritz" ) 
                                {
                                    $encrypted_data = $encryptor->encrypt($plain_data);                                
                                }
                                elsif($self->{method} =~ /^chacha20/ )
                                {
                                    if($self->{method} eq 'chacha20-ietf')
                                    {
                                        #my $pt_len = length($plain_data)  % 64;
                                        my $pad_len = $encrypt_counter % 64;
                                        my $padded_plain_data  = Net::Shadowsocks::_add_padding($plain_data,$pad_len); 
                                        my $padded_encrypted_data = $encryptor->chacha20_ietf_xor_ic($padded_plain_data,$encrypt_nonce,$encrypt_counter /64 ,$key);
                                        #$encrypted_data = $encryptor->chacha20_ietf_xor_ic($plain_data,$encrypt_nonce,$encrypt_counter / 64,$key);
                                        $encrypted_data = Net::Shadowsocks::_remove_padding($padded_encrypted_data,$pad_len);
                                        #$decrypted_data = $encryptor->chacha20_ietf_xor($plain_data,$iv,$key);
                                        $encrypt_counter += length($plain_data) ;
                                    }
                                    else
                                    {
                                        my $header_len_pt = pack('n',length($plain_data));
                                        my $header_len_ct_withtag = $encryptor ->ietf_encrypt($header_len_pt,"",$encrypt_nonce,$encrypt_subkey);
                                        $encrypt_nonce = $encrypt_nonce->increment();
                                        #carp $encrypt_nonce;
                                        #carp ascii_to_hex($encrypt_nonce);
                                        my $header_ct_withtag  =  $encryptor->ietf_encrypt($plain_data,"",$encrypt_nonce,$encrypt_subkey);
                                        $encrypt_nonce = $encrypt_nonce->increment();
                                        #carp $encrypt_nonce;
                                        #carp ascii_to_hex($encrypt_nonce);
                                        $encrypted_data = $header_len_ct_withtag . $header_ct_withtag;
                                        #carp length($encrypted_data);                                      
                                    }
                                }
                                elsif($self->{method} =~ /gcm$/)
                                {
                                    #carp $encrypt_nonce;
                                    $encryptor->reset();
                                    $encryptor->iv_add($encrypt_nonce);
                                    #carp length($plain_data);
                                    my $header_len_pt = pack('n',length($plain_data));
                                    #carp $header_len_pt;
                                    #carp length($header_len_pt);
                                    $encryptor->adata_add("");
                                    my $header_len_ct = $encryptor ->encrypt_add($header_len_pt,);
                                    my $header_len_tag = $encryptor->encrypt_done();
                                    $encrypt_nonce = $encrypt_nonce->increment();
                                    $encryptor->reset();
                                    $encryptor->iv_add($encrypt_nonce);
                                    $encryptor->adata_add("");
                                    my $header_ct = $encryptor->encrypt_add($plain_data);
                                    my $header_tag = $encryptor->encrypt_done();
                                    $encrypt_nonce = $encrypt_nonce->increment();
                                    #$encryptor->reset();
                                    $encrypted_data = $header_len_ct . $header_len_tag . $header_ct . $header_tag;
                                    #carp length($encrypted_data);
                                }

                                else
                                {
                                      $encrypted_data = $encryptor->encrypt($plain_data,$key,$iv);
                                }
                                
                                my $datatosend;
                                if ( $mode == 0  ) 
                                {
                                    $datatosend = $iv . $encrypted_data;
                                    $mode = 1;
                                }
                                else 
                                {
                                    $datatosend = $encrypted_data;
                                }
                                if (defined($remotehandler))
                                { 
                                    $remotehandler->push_write($datatosend);
                                }
                                else
                                {
                                     AE::log error => "lost connection to remote server";
                                     $stage = 0;
                                     $chandle ->destroy();
                                }
                            }
                        }
                        $chandle->{rbuf} = undef;
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

Net::Shadowsocks::Client - Shadowsocks protocol client module.

=head1 VERSION

Version 0.9.3.4

=head1 SYNOPSIS

    use Net::Shadowsocks::Client;
    
=head1 DESCRIPTION

1. A total of 34 encryption methods are supported:

	aes-128-cfb aes-128-ctr aes-128-gcm aes-128-ofb
	aes-192-cfb aes-192-ctr aes-192-gcm aes-192-ofb
	aes-256-cfb aes-256-ctr aes-256-gcm aes-256-ofb
	camellia-128-cfb camellia-128-ctr camellia-128-ofb
	camellia-192-cfb camellia-192-ctr camellia-192-ofb
	camellia-256-cfb camellia-256-ctr camellia-256-ofb
	chacha20-ietf chacha20-ietf-poly1305
	rc4-md5
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

=head1 METHODS

=head2 new

    The new constructor lets you create a new Net::Shadowsocks::Client object or dies on error.

    Example use:

    my $foo = Net::Shadowsocks::Client->new(
    local_address => 'localhost',
    local_port => 1491,
    password => '49923641',
    server => 'jp.ssip.club',
    server_port => 23333,
    method => 'spritz',
    );

    This is all you need to do. Take a look at client.pl under eg directory for a compelete example on how to
    use the client module.

=head1 SEE ALSO

L<Shadowsocks Official website |https://shadowsocks.org/en/index.html>,L<Shadowsocks on Wikipedia |https://en.wikipedia.org/wiki/Shadowsocks>

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
