 package Net::Shadowsocks::Server;

    # ABSTRACT: Shadowsocks protocol server module.
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
    use Crypt::KeyDerivation;
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
    use Digest::SHA;
    use Net::Shadowsocks;
    use Net::Shadowsocks qw(_get_algorithm _get_mode _get_key_size _EVP_BytesToKey _initialize_cipher);
    use Socket qw(IPPROTO_TCP TCP_FASTOPEN SOL_SOCKET SO_REUSEPORT SO_REUSEADDR);
    #use String::HexConvert ':all';
    
    our $VERSION = '0.9.1';
    
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

                my ( $encryptor, $decryptor, $key, $encrypt_subkey,$iv,$encrypt_nonce,$decrypt_nonce ) = Net::Shadowsocks::_initialize_cipher( $self->{method},$self->{password} );
                my $decrypt_subkey;
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
                        my $chandler = shift;
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
                        my $chandle = shift;
                        my $client_buffer = $chandle->rbuf();

                        if ( length($client_buffer) == 0 ) 
                        {
                            return;
                        }
                        else 
                        {
                            my $incoming_data = $client_buffer;
                            my $decrypted_data = '';
                            unless ( defined($client_iv) ) 
                            {
                                 if(length($incoming_data) < length($iv) )
                                 {
                                     return;
                                 } 
                                 else
                                 {
                                    $client_iv = substr( $client_buffer, 0, length($iv) );
                                    $incoming_data = substr( $client_buffer, length($iv) );
                                    $chandle->{rbuf} = $incoming_data;
=cut for comment
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
=cut
                                    if ( !defined($self->{method}) or $self->{method} eq 'spritz' ) 
                                    {
                                        $decryptor = Crypt::Spritz::Cipher->new($key,$client_iv);
                                    }
                                    elsif ( $self->{method} eq 'rabbit' ) 
                                    {
                                        my $md = Digest::MD5->new();
                                        $md->add($key .$client_iv );
                                        #$md->add($client_iv);
                                        my $decrypt_rabbit_key = $md->digest();
                                        $decryptor = Crypt::Rabbit->new($decrypt_rabbit_key);
                                    }
                                    elsif($self->{method} =~ /gcm$/ or $self->{method} =~ /poly1305$/)
                                    {
                                        $decrypt_subkey = hkdf($key,$client_iv,'SHA1',Net::Shadowsocks::_get_key_size($self->{method}),"ss-subkey");
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
                                 if ($mode == 0)
                                 {
=cut for comment
                                     if ($self->{method} =~ /^rc4/ )
                                     {
                                          $decrypted_data = Mcrypt::mcrypt_decrypt($decryptor, $incoming_data );
                                     }
=cut
                                     if ($self->{method} eq "rabbit" or $self->{method} eq "spritz")
                                     {
                                          $decrypted_data = $decryptor->decrypt($incoming_data );
                                     }
                                     elsif($self->{method} =~ /^chacha20/)
                                     {
                                        if ($self->{method} eq 'chacha20-ietf')
                                        {
                                           #$decrypted_data = $decryptor->process($incoming_data);
                                           #my $ct_len = length($incoming_data)  % 64;
                                           #my $pad_len = 64 - $ct_len;
                                           #my $padded_incoming_data  = Net::Shadowsocks::_add_padding($incoming_data,$pad_len); 
                                           #my $padded_decrypted_data = $decryptor->chacha20_ietf_xor_ic($padded_incoming_data,$client_iv,$decrypt_counter,$key);
                                           $decrypted_data = $decryptor->chacha20_ietf_xor_ic($incoming_data,$client_iv,$decrypt_counter,$key);
                                           #$decrypted_data = Net::Shadowsocks::_remove_padding($padded_decrypted_data,$pad_len);
                                           #$decrypted_data = $decryptor->chacha20_ietf_xor($incoming_data,$client_iv,$key);
                                           $decrypt_counter += length($incoming_data) / 64;
                                       }
                                       else
                                       {
                                           while (length($incoming_data) > 0)
                                           {
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
                                                                $data_len_pt = $decryptor->ietf_decrypt($data_len_ct, '', $decrypt_nonce, $decrypt_subkey);
                                                            };
                                                            if ( $@ ) 
                                                            {
                                                                AE::log error =>  "data length forged!";
                                                                $chandle->destroy();
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
                                                                    $decrypted_data .= $decryptor->ietf_decrypt(substr($incoming_data,18,$data_len + 16),'',$decrypt_nonce,$decrypt_subkey);
                                                                     if ( $@ ) 
                                                                     {
                                                                         AE::log error =>  "data forged!";
                                                                         $chandle->destroy();
                                                                     }
                                                                     else
                                                                     {
                                                                         $decrypt_nonce = $decrypt_nonce->increment();  
                                                                         $incoming_data = substr($incoming_data,$chunk_len);                                                                       
                                                                         $chandle->{rbuf} = $incoming_data;  
                                                                         carp "more chunk to process" if (length($incoming_data ) > 0);                                                                      
                                                                     }  
                                                                }      
                                                            }
                                                        }
                                                    }
                                       }
                                    }
                                     elsif($self->{method} =~ /gcm$/)
                                     {
                                         while (length($incoming_data) > 0)
                                         {
                                                if (length($incoming_data) < 34)
                                                {
                                                            return;
                                                }
                                                else
                                                {
                                                            my $header_len_ct = substr($incoming_data,0,2); 
                                                            $decryptor->reset();
                                                            $decryptor->iv_add($decrypt_nonce);
                                                            $decryptor->adata_add('');
                                                            my $header_len_pt = $decryptor->decrypt_add($header_len_ct);
                                                            my $header_len_tag = substr($incoming_data,2,16);
                                                            my $length_result = $decryptor->decrypt_done($header_len_tag);
                                                            if (!$length_result)
                                                            {
                                                                AE::log error =>  "data length forged!";
                                                                $chandle->destroy();
                                                            } 
                                                            else 
                                                            {
                                                                my $header_len = unpack('n',$header_len_pt); 
                                                                #carp "Decrypted data length: $header_len\n";
                                                                my $chunk_len = $header_len + 34;
                                                                if (length($incoming_data) < $chunk_len)
                                                                {
                                                                    return;
                                                                }
                                                                else
                                                                {
                                                                    $decrypt_nonce = $decrypt_nonce->increment();
                                                                    $decryptor->reset();
                                                                    $decryptor->iv_add($decrypt_nonce);
                                                                    $decryptor->adata_add('');
                                                                    $decrypted_data .= $decryptor->decrypt_add(substr($incoming_data,18,$header_len ));
                                                                    my $header_tag = substr($incoming_data,18 + $header_len,16);
                                                                    my $header_result = $decryptor->decrypt_done($header_tag);
                                                                     if ( !$header_result ) 
                                                                     {
                                                                         AE::log error =>  "data forged!";
                                                                         $chandle->destroy();
                                                                     }
                                                                     else
                                                                     {
                                                                         $decrypt_nonce = $decrypt_nonce->increment();  
                                                                         $decryptor->reset();
                                                                         $incoming_data = substr($incoming_data,$chunk_len);                                                                       
                                                                         $chandle->{rbuf} = $incoming_data;   
                                                                         carp "more chunk to process" if (length($incoming_data ) > 0);                                                                      
                                                                     }  
                                                                }      
                                                            }
                                                        }
                                                    }
                                    }

                                     else 
                                     {
                                          $decrypted_data = $decryptor->decrypt($incoming_data,$key,$client_iv);
                                     }
                                     if (length($decrypted_data) > 0)
                                     {                                
                                          my $addrtype = ord( substr( $decrypted_data, 0, 1 ) );
                                          if (    $addrtype != 1 and $addrtype != 3 and $addrtype != 4 )
                                          {
                                              AE::log error => "Invalid address type";
                                              $chandle->destroy();
                                              #return;
                                          }
                                          else
                                          {
                                              my $dest_addr;
                                              my $dest_port;

                                              if ( $addrtype == 1 ) 
                                              {
                                                  if ( length($decrypted_data) >= 7 ) 
                                                  {
                                                      $dest_addr = format_address(substr( $decrypted_data, 1, 4 ) );
                                                      $dest_port = unpack( 'n',substr( $decrypted_data, 5, 2 ) );
                                                      $decrypted_data = substr( $decrypted_data, 7 );
                                                  }
                                                  else 
                                                  {
                                                      return;
                                                  }
                                              }
                                              elsif ( $addrtype == 3 ) 
                                              {
                                                  if ( length($decrypted_data) > 4 ) 
                                                  {
                                                      my $addr_len = ord( substr( $decrypted_data, 1, 1 ) );
                                                      if (length($decrypted_data) >= 4 + $addr_len )
                                                      {
                                                          $dest_addr = substr( $decrypted_data, 2,$addr_len );
                                                          $dest_port = unpack('n',substr($decrypted_data,2 + $addr_len,2));
                                                          $decrypted_data = substr( $decrypted_data,4 + $addr_len );
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
                                                  if ( length($decrypted_data) >= 19 ) 
                                                  {
                                                      $dest_addr = format_address(substr( $decrypted_data, 1, 16 ) );
                                                      $dest_port = unpack( "n", substr( $decrypted_data, 17, 2 ) );
                                                      $decrypted_data = substr( $decrypted_data, 19 );
                                                  }
                                                  else 
                                                  {
                                                      return;
                                                  }
                                              }
                                              $remotehandler = AnyEvent::Handle->new
                                              (
                                                  autocork   => 1,
                                                  keepalive  => 1,
                                                  no_delay   => 1,
                                                  connect    => [ $dest_addr, $dest_port ],
                                                  on_connect => sub 
                                                  {
                                                      my ($rhandle,  $peerhost,$peerport, $retry) = @_;
                                                      #$mode = 1;
                                                      AE::log info => "Connected with $peerhost : $peerport."; 
                                                      if(length($decrypted_data) > 0)
                                                      {
                                                          $rhandle->push_write($decrypted_data);
                                                      
                                                          if ($self->{method} !~ /gcm$/ and $self->{method} !~ /poly1305$/)
                                                          {
                                                              $chandle->{rbuf} = '';
                                                          }
                                                      }
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
                                                      my $remote_buffer = $rhandle->rbuf();
                                                      my $plain_data = $remote_buffer;
                                                      my $encrypted_data;
=cut for comment                                                
                                                      if ( $self->{method} =~ /^rc4/)
                                                      {
                                                          $encrypted_data = Mcrypt::mcrypt_encrypt($encryptor, $plain_data );    
                                                      }
=cut
                                                      if ( $self->{method} eq "rabbit" or $self->{method} eq "spritz")
                                                      {
                                                          $encrypted_data = $encryptor->encrypt($plain_data );    
                                                      }
                                                      elsif($self->{method} =~ /^chacha20/)
                                                      {
                                                          if($self->{method} eq 'chacha20-ietf')
                                                          {
                                                              #$encrypted_data = $encryptor->process($plain_data);
                                                              #my $pt_len = length($plain_data)  % 64;
                                                              #my $pad_len = 64 - $pt_len;
                                                              #my $padded_plain_data  = Net::Shadowsocks::_add_padding($plain_data,$pad_len);    
                                                              #my $padded_encrypted_data = $encryptor->chacha20_ietf_xor_ic($padded_plain_data,$iv,$encrypt_counter,$key);
                                                              $encrypted_data = $encryptor->chacha20_ietf_xor_ic($plain_data,$iv,$encrypt_counter,$key);
                                                              #$encrypted_data = $encryptor->chacha20_ietf_xor($plain_data,$iv,$key);
                                                              #$encrypted_data = Net::Shadowsocks::_remove_padding($padded_encrypted_data,$pad_len);
                                                              $encrypt_counter += length($plain_data) / 64;
                                                          }
                                                          else
                                                          {
                                                              my $data_len_pt = pack('n',length($plain_data));
                                                              my $data_len_ct_withtag = $encryptor ->ietf_encrypt($data_len_pt,'',$encrypt_nonce,$encrypt_subkey);
                                                              $encrypt_nonce = $encrypt_nonce->increment();
                                                              my $data_ct_withtag  =  $encryptor->ietf_encrypt($plain_data,'',$encrypt_nonce,$encrypt_subkey);
                                                              $encrypt_nonce = $encrypt_nonce->increment();
                                                              $encrypted_data = $data_len_ct_withtag . $data_ct_withtag;
                                                              carp length($encrypted_data);
                                                          }
                                                      }
                                                      elsif($self->{method} =~ /gcm$/)
                                                      {
                                                          carp $encrypt_nonce;
                                                          $encryptor->iv_add($encrypt_nonce);
                                                          carp length($plain_data);
                                                          my $header_len_pt = pack('n',length($plain_data));
                                                          carp $header_len_pt;
                                                          carp length($header_len_pt);
                                                          $encryptor->adata_add('');
                                                          my $header_len_ct = $encryptor ->encrypt_add($header_len_pt,);
                                                          my $header_len_tag = $encryptor->encrypt_done();
                                                          $encrypt_nonce = $encrypt_nonce->increment();
                                                          $encryptor->reset();
                                                          $encryptor->iv_add($encrypt_nonce);
                                                          $encryptor->adata_add('');
                                                          my $header_ct = $encryptor->encrypt_add($plain_data);
                                                          my $header_tag = $encryptor->encrypt_done();
                                                          $encrypt_nonce = $encrypt_nonce->increment();
                                                          $encryptor->reset();
                                                          $encrypted_data = $header_len_ct . $header_len_tag . $header_ct . $header_tag;
                                                          carp length($encrypted_data);
                                                      }
                                                      else 
                                                      {
                                                          $encrypted_data = $encryptor->encrypt($plain_data,$key,$iv);    
                                                      }
                                        
                                                      my $datatosend;
                                                      if ( $mode == 0 ) 
                                                      {
                                                          $datatosend = $iv . $encrypted_data;
                                                          $mode       = 1;
                                                      }
                                                      else 
                                                      {
                                                          $datatosend = $encrypted_data;
                                                      }
                                                      $clienthandler->push_write($datatosend);
                                                      $rhandle->{rbuf} = '';
                                                  }
                                             );
                                        }
                                   }
                                   else
                                   {
                                   }
                               }
                               else
                               {
=cut for comment
                                     if ($self->{method} =~ /^rc4/ )
                                     {
                                          $decrypted_data = Mcrypt::mcrypt_decrypt($decryptor, $incoming_data );
                                     }
=cut
                                     if ($self->{method} eq "rabbit" or $self->{method} eq "spritz")
                                     {
                                          $decrypted_data = $decryptor->decrypt($incoming_data );
                                     }
                                     elsif($self->{method} =~ /^chacha20/)
                                     {
                                        if ($self->{method} eq 'chacha20-ietf')
                                        {
                                           #$decrypted_data = $decryptor->process($incoming_data);
                                           #my $ct_len = length($incoming_data)  % 64;
                                           #my $pad_len = 64 - $ct_len;
                                           #my $padded_incoming_data  = Net::Shadowsocks::_add_padding($incoming_data,$pad_len); 
                                           #my $padded_decrypted_data = $decryptor->chacha20_ietf_xor_ic($padded_incoming_data,$client_iv,$decrypt_counter,$key);
                                           $decrypted_data = $decryptor->chacha20_ietf_xor_ic($incoming_data,$client_iv,$decrypt_counter,$key);
                                           #$decrypted_data = Net::Shadowsocks::_remove_padding($padded_decrypted_data,$pad_len);
                                           #$decrypted_data = $decryptor->chacha20_ietf_xor($incoming_data,$client_iv,$key);
                                           $decrypt_counter += length($incoming_data) / 64;
                                       }
                                       else
                                       {
                                           while (length($incoming_data) > 0)
                                           {
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
                                                                $data_len_pt = $decryptor->ietf_decrypt($data_len_ct, '', $decrypt_nonce, $decrypt_subkey);
                                                            };
                                                            if ( $@ ) 
                                                            {
                                                                AE::log error =>  "data length forged!";
                                                                $chandle->destroy();
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
                                                                    $decrypted_data .= $decryptor->ietf_decrypt(substr($incoming_data,18,$data_len + 16),'',$decrypt_nonce,$decrypt_subkey);
                                                                     if ( $@ ) 
                                                                     {
                                                                         AE::log error =>  "data forged!";
                                                                         $chandle->destroy();
                                                                     }
                                                                     else
                                                                     {
                                                                         $decrypt_nonce = $decrypt_nonce->increment();          
                                                                         $incoming_data = substr($incoming_data,$chunk_len);                                                                       
                                                                         $chandle->{rbuf} = $incoming_data;   
                                                                         carp "more chunk to process" if (length($incoming_data ) > 0);                                                                                                            
                                                                     }  
                                                                }      
                                                            }
                                                        }
                                                    }
                                       }
                                    }
                                     elsif($self->{method} =~ /gcm$/)
                                     {
                                         while (length($incoming_data) > 0)
                                         {
                                               if (length($incoming_data) < 34)
                                               {
                                                            return;
                                               }
                                               else
                                               {
                                                            my $header_len_ct = substr($incoming_data,0,2); 
                                                            $decryptor->iv_add($decrypt_nonce);
                                                            $decryptor->adata_add('');
                                                            my $header_len_pt = $decryptor->decrypt_add($header_len_ct);
                                                            my $header_len_tag = substr($incoming_data,2,16);
                                                            my $length_result = $decryptor->decrypt_done($header_len_tag);
                                                            if (!$length_result)
                                                            {
                                                                AE::log error =>  "data length forged!";
                                                                $chandle->destroy();
                                                            } 
                                                            else 
                                                            {
                                                                my $header_len = unpack('n',$header_len_pt); 
                                                                #carp "Decrypted data length: $header_len\n";
                                                                my $chunk_len = $header_len + 34;
                                                                if (length($incoming_data) < $chunk_len)
                                                                {
                                                                    return;
                                                                }
                                                                else
                                                                {
                                                                    $decrypt_nonce = $decrypt_nonce->increment();
                                                                    $decryptor->reset();
                                                                    $decryptor->iv_add($decrypt_nonce);
                                                                    $decryptor->adata_add('');
                                                                    $decrypted_data = $decryptor->decrypt_add(substr($incoming_data,18,$header_len ));
                                                                    my $header_tag = substr($incoming_data,18 + $header_len,16);
                                                                    my $header_result = $decryptor->decrypt_done($header_tag);
                                                                     if ( !$header_result ) 
                                                                     {
                                                                         AE::log error =>  "data forged!";
                                                                         $chandle->destroy();
                                                                     }
                                                                     else
                                                                     {
                                                                         $decrypt_nonce = $decrypt_nonce->increment();  
                                                                         $decryptor->reset();      
                                                                         $incoming_data = substr($incoming_data,$chunk_len);                                                                       
                                                                         $chandle->{rbuf} = $incoming_data;     
                                                                          carp "more chunk to process" if (length($incoming_data ) > 0);                                                                
                                                                     }  
                                                                }      
                                                            }
                                                        }
                                                    }
                                    }

                                    else 
                                     {
                                          $decrypted_data = $decryptor->decrypt($incoming_data,$key,$client_iv);
                                     }
                                     if (defined($remotehandler))
                                     {
                                          $remotehandler->push_write($decrypted_data);
                                     }
                                     else
                                     { 
                                         AE::log error => "lost connection to remote";
                                         $mode = 0;
                                         $chandle ->destroy();
                                     }  
                                }
                            }
                       } 
                       if ($self->{method} !~ /gcm$/ and $self->{method} !~ /poly1305$/)
                       {
                            $chandle->{rbuf} = '';
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

Net::Shadowsocks::Server - Shadowsocks protocol server.

=head1 VERSION

Version 0.9.0

=head1 SYNOPSIS

    use Net::Shadowsocks::Server;
    
=head1 DESCRIPTION

1. A total of 34 encryption methods are supported:

	aes-128-cfb aes-128-ctr aes-128-gcm aes-128-ofb
	aes-192-cfb aes-192-ctr aes-192-gcm aes-192-ofb
	aes-256-cfb aes-256-ctr aes-256-gcm aes-256-ofb
	camellia-128-cfb camellia-128-ctr camellia-128-ofb
	camellia-192-cfb camellia-192-ctr camellia-192-ofb
	camellia-256-cfb camellia-256-ctr camellia-256-ofb
	chacha20-ietf chacha20-ietf-poly1305
	rabbit
	rc6-128-cfb rc6-128-ctr rc6-128-ofb
	rc6-192-cfb rc6-192-ctr rc6-192-ofb
	rc6-256-cfb rc6-256-ctr rc6-256-ofb
	spritz

2.The following ciphers deprecated by Shadowsocks are not supported: 

      bf-cfb chacha20 salsa20 rc4-md5

3.The following ciphers recommended by Shadowsocks are not supported yet: 
 
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

    my $foo = Net::Shadowsocks::Server->new(
    password => ' 49923641 ',
    server => ' jp . ssip . club ',
    server_port => 23333,
    method => 'rc6',
    );

    This is all you need to do. Take a look at server.pl under eg directory for a compelete example on how to
    use the server module.

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

