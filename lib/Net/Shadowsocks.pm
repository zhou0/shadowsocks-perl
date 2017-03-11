package Net::Shadowsocks;

# ABSTRACT: the asynchronous, non-blocking shadowsocks client and server. 
# KEYWORDS: socks shadowsocks rfc1928 Great Firewall Internet censorship in China
use 5.006;
use strict;
use warnings;
BEGIN 
{
       my $_win32 = ($^O eq "MSWin32") ? 1 : 0;                 
       if ($_win32) 
       {
       }
       else 
       {
           eval "use Crypt::NaCl::Sodium";
           die "$@" if $@;
       }
}
use AnyEvent::Log;
use Carp;
use Crypt::AuthEnc::GCM;
use Crypt::Cipher::AES;
use Crypt::Cipher::Camellia;
use Crypt::Cipher::RC6;
use Crypt::KeyDerivation qw(hkdf);
use Crypt::Mode::CFB;
use Crypt::Mode::CTR;
use Crypt::Mode::OFB;
#use Crypt::NaCl::Sodium;
use Crypt::Rabbit;
use Crypt::Random qw( makerandom_octet );
#use Crypt::RC4::XS;
use Crypt::Spritz;
use Digest::MD5;
use Digest::SHA;
#use Mcrypt qw(:FUNCS);
#use String::HexConvert ':all';

our $VERSION = '0.9.1';

our %_ciphers = 
    (
        "aes-128-cfb"  => ['AES','cfb',16,16],
        #"aes-128-cfb"  => ['rijndael-128','ncfb',16,16],
        "aes-128-ctr"  => ['AES','ctr',16,16],
        # "aes-128-ctr"  => ['rijndael-128','ctr',16,16],
         "aes-128-gcm"  => ['AES',undef,16,16],
        #"aes-128-ofb" => ['rijndael-128','nofb',16,16],
        "aes-128-ofb" => ['AES','ofb',16,16],    
        "aes-192-cfb" => ['AES','cfb',24,16],
        #"aes-192-cfb"  => ['rijndael-128','ncfb',24,16],
        "aes-192-ctr"  => ['AES','ctr',24,16],
        #"aes-192-ctr"  => ['rijndael-128','ctr',24,16],
         "aes-192-gcm"  => ['AES',undef,24,16],
        #"aes-192-ofb" => ['rijndael-128','nofb',24,16],
        "aes-192-ofb" => ['AES','ofb',24,16],
        "aes-256-cfb"  => ['AES','cfb',32,16],
        #"aes-256-cfb"  => ['rijndael-128','ncfb',32,16],
        "aes-256-ctr"  => ['AES','ctr',32,16],
        #"aes-256-ctr"  => ['rijndael-128','ctr',32,16],
        "aes-256-gcm"  => ['AES',undef,32,16],
        #"aes-256-ofb"  => ['rijndael-128','nofb',32,16],
        "aes-256-ofb"  => ['AES','ofb',32,16],
        "camellia-128-cfb" => ['Camellia','cfb',16,16],
        "camellia-128-ctr" => ['Camellia','ctr',16,16],
        "camellia-128-ofb" => ['Camellia','ofb',16,16],
        "camellia-192-cfb" => ['Camellia','cfb',24,16],
        "camellia-192-ctr" => ['Camellia','ctr',24,16],
        "camellia-192-ofb" => ['Camellia','ofb',24,16],
        "camellia-256-cfb" => ['Camellia','cfb',32,16],
        "camellia-256-ctr" => ['Camellia','ctr',32,16],
        "camellia-256-ofb" => ['Camellia','ofb',32,16],
        "chacha20-ietf" => [undef,undef,32,12],
        "chacha20-ietf-poly1305" =>  [undef,undef,32,12],
        "rabbit" => ['rabbit','stream',16,16],        
        #"rc4-md5"  => ['arcfour','stream',16,16],
        #"rc4-sha" => ['arcfour','stream',16,20],
        "rc6-128-cfb" => ['RC6','cfb',16,16],
        "rc6-128-ctr" => ['RC6','ctr',16,16],
        "rc6-128-ofb" => ['RC6','ofb',16,16],
        "rc6-192-cfb" => ['RC6','cfb',24,16],
        "rc6-192-ctr" => ['RC6','ctr',24,16],
        "rc6-192-ofb" => ['RC6','ofb',24,16],
        "rc6-256-cfb" => ['RC6','cfb',32,16],
        "rc6-256-ctr" => ['RC6','ctr',32,16],
        "rc6-256-ofb" => ['RC6','ofb',32,16],
        "spritz" =>  ['spritz','stream',16,16], 
    );

sub _EVP_BytesToKey($$$$$) 
{
    my ( $key_len, $iv_len, $salt, $data, $count ) = @_;
    my $md_buf = '';
    my $key    = '';
    if ( $data eq '' ) 
    {
        return $key;
    }
    my $addmd = 0;
    for ( ; ; ) 
    {
        my $md;
        $md = Digest::MD5->new;
        if ( $addmd++ > 0 ) 
        {
            $md->add($md_buf);
        }
        $md->add($data);
        if ( $salt ne '' ) 
        {
            $md->add_bits( $salt, 64 );
        }
        $md_buf = $md->digest();
        for ( my $i = 1 ; $i < $count ; $i++ ) 
        {
            $md->reset();
            $md->add($md_buf);
            $md_buf = $md->digest();
        }
        $key .= $md_buf;
        if ( length($key) >= $key_len ) 
        {
            $key = substr( $key, 0, $key_len );
            last;
        }
    }
    return $key;
}

sub _initialize_cipher($$) 
{
    my $_method   = shift;
    my $_password = shift;

    my $_encryptor;
    my $_decryptor;
    my $_key;
    my $_encrypt_subkey;
    my $_iv;
    my $_encrypt_nonce;
    my $_decrypt_nonce;
    if (!defined($_method))
    {
        AE::log info => "Encryption method undefinde, using spritz." ;

        $_key = _EVP_BytesToKey(16, 16, '', $_password, 1 );
        $_iv = makerandom_octet( Length => 16 );
        $_encryptor = Crypt::Spritz::Cipher->new($_key, $_iv);
    }
    else
    {
        if($_method =~ /^chacha20/)
        {
            if ($_method eq 'chacha20-ietf')
            {
                $_encryptor = Crypt::NaCl::Sodium->stream();
                #$_key = $_encryptor->chacha20_keygen();
                $_key = _EVP_BytesToKey($_ciphers{$_method}->[2], $_ciphers{$_method}->[3] , '', $_password, 1 );
                $_encrypt_nonce = $_encryptor->chacha20_ietf_nonce();
                $_decryptor = Crypt::NaCl::Sodium->stream();
                $_iv = $_encrypt_nonce;
            }
            else
            {
                $_encryptor = Crypt::NaCl::Sodium->aead();
                #$_key = $_encryptor->chacha20_keygen();
                $_key = _EVP_BytesToKey($_ciphers{$_method}->[2], $_ciphers{$_method}->[3] , '', $_password, 1 );
                my $_encrypt_salt = makerandom_octet( Length => $_ciphers{$_method}->[2]); 
                $_encrypt_subkey = hkdf($_key,$_encrypt_salt,'SHA1',$_ciphers{$_method}->[2],"ss-subkey");
                #carp ascii_to_hex($_encrypt_subkey);
                $_decryptor = Crypt::NaCl::Sodium->aead();
                $_iv = $_encrypt_salt;
                $_encrypt_nonce = $_encryptor->ietf_nonce("\0");
                $_decrypt_nonce = $_decryptor->ietf_nonce("\0");
                #carp $_encrypt_nonce;
                #carp ascii_to_hex($_encrypt_nonce);
            }
        }
        elsif($_method =~ /gcm$/ )
        {
            $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
            my $_encrypt_salt = makerandom_octet( Length => $_ciphers{$_method}->[2]); 
            my $_encrypt_subkey = hkdf($_key,$_encrypt_salt,'SHA1',$_ciphers{$_method}->[2],"ss-subkey");
            $_iv = $_encrypt_salt; 
            $_encryptor = Crypt::AuthEnc::GCM->new('AES', $_encrypt_subkey);
            $_encrypt_nonce = Data::BytesLocker->new("\0" x 12);
            $_decrypt_nonce = Data::BytesLocker->new("\0" x 12);
        }
=cut for comment           
            elsif($_method =~ /^rc4/ )
            {
                $_encryptor = Mcrypt::mcrypt_load($_ciphers{$_method}->[0],'',$_ciphers{$_method}->[1] , '' );
                $_decryptor = Mcrypt::mcrypt_load($_ciphers{$_method}->[0] ,'',$_ciphers{$_method}->[1], '' );
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] );

                    my $encrypt_rc4_key;
                    if ($_method eq 'rc4-md5' )
                    {
                       my $md = Digest::MD5->new();
                       $md->add($_key . $_iv);
                       $encrypt_rc4_key = $md->digest();
                    }
                    elsif($_method eq 'rc4-sha' )
                    {
                       my $sha = Digest::SHA->new();
                       $sha->add($_key . $_iv);
                       $encrypt_rc4_key = substr($sha->digest(),0,16);
                    }
                    Mcrypt::mcrypt_init($_encryptor, $encrypt_rc4_key, '' );
            }
=cut            
        elsif($_method eq 'rabbit')
        {
            $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
            $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] );
            my $md = Digest::MD5->new();
            $md->add($_key . $_iv);
            my $encrypt_rabbit_key = $md->digest();
            $_encryptor = Crypt::Rabbit->new($encrypt_rabbit_key);
            #$_decryptor = Crypt::Rabbit->new($encrypted_rabbit_key);
        }
        elsif($_method eq "spritz") 
        {
            $_key = _EVP_BytesToKey(16, 16, '', $_password, 1 );
            $_iv = makerandom_octet( Length => 16 );
            $_encryptor = Crypt::Spritz::Cipher->new($_key, $_iv);
        }
        elsif( ($_method =~ /^aes/  or $_method =~ /^camellia/ or $_method =~ /^rc6/ ) and $_method !~ /gcm$/ )
        {
            if($_method =~ /cfb$/)
            {
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] ); 
                $_encryptor = Crypt::Mode::CFB->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::CFB->new($_ciphers{$_method}->[0]);
            }
             elsif($_method =~ /ctr$/)
            {
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] ); 
                $_encryptor = Crypt::Mode::CTR->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::CTR->new($_ciphers{$_method}->[0]);
            }
            elsif($_method =~ /ofb$/)
            {
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] ); 
                $_encryptor = Crypt::Mode::OFB->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::OFB->new($_ciphers{$_method}->[0]);
            }
        }
    }
    return $_encryptor, $_decryptor, $_key, $_encrypt_subkey,$_iv, $_encrypt_nonce,$_decrypt_nonce;
}

sub _get_algorithm($)
{
    my $_method   = shift;
    if (defined($_method))
    {
        return $_ciphers{$_method}->[0];
    }
    else
    {
        return 'arcfour';
    }
    }

sub _get_mode($)
{
    my $_method   = shift;
    if (defined($_method))
    {
        return $_ciphers{$_method}->[1];
    }
    else
    {
        return 'stream'; 
    }
}

sub _get_key_size($)
{
    my $_method = shift;
    if (defined($_method))
    {
        return $_ciphers{$_method}->[2];   
    }
    else
    {
        return 16;
    }
}

sub _get_iv_size($)
{
    my $_method = shift;
    if (defined($_method))
    {
        return $_ciphers{$_method}->[3];   
    }
    else
    {
        return 16;
    }
}

sub _add_padding($$$)
{
        # add required padding so we can recover the original string length after decryption
        # (padding bytes have value set to padding length)
        my $_method = shift;
        my $_pt = shift;
        my $_pad_len = shift;
        my $_block_size = _get_key_size($_method);
        #my $_pt_len = length($_pt)  % $_block_size;
        #my $_pad_len = $_block_size - $_pt_len;
        $_pt .= (chr($_pad_len)) x $_pad_len unless $_pad_len == $_block_size;
        #$_pt = (chr(0)) x $_pad_len . $_pt unless $_pad_len == $_block_size;
        return $_pt;
}



sub _remove_padding($$$)
{
        # remove padding if necessary (padding byte value gives length of padding)
        my $_method = shift;
        my $_ct = shift;
        my $_pad_len = shift;
        my $_ct_len = length($_ct);
        my $_block_size = _get_key_size($_method);
        #my $_pad_len = ord(substr($_ct, -1, 1));
        if ($_pad_len > $_block_size)
        {
            AE::log error => "invalid pad byte";
        }
        else
        {
        $_ct  = substr($_ct, 0, $_ct_len - $_pad_len);
        #$_ct  = substr($_ct, $_pad_len, $_ct_len - $_pad_len);
        }
        return $_ct;
}
1;    # End of Net::Shadowsocks

 __END__

=pod

=encoding utf8

=head1 NAME

Net::Shadowsocks - the asynchronous, non-blocking shadowsocks client and server. 

=head1 VERSION

Version 0.9.0

=head1 SYNOPSIS
    
=head1 DESCRIPTION

Shadowsocks is a secure transport protocol based on SOCKS Protocol Version 5 (RFC 1928 ).Net::Shadowsocks is a Perl implementation of the shadowsocks (Chinese: 影梭) protocol client and server. ssclient.pl is the asynchronous, non-blocking shadowsocks client. ssserver.pl is the asynchronous, non-blocking shadowsocks server. Run ssclient.pl and/or ssserver.pl and follow instructions.

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

