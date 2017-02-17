package Net::Shadowsocks;

# ABSTRACT: the asynchronous, non-blocking shadowsocks client and server. 
use 5.006;
use strict;
use warnings;
use AnyEvent::Log;
use Carp;
use Crypt::Cipher::AES;
use Crypt::Cipher::Camellia;
use Crypt::Cipher::RC6;
use Crypt::Mode::CBC;
use Crypt::Mode::CFB;
use Crypt::Mode::CTR;
use Crypt::Mode::OFB;
use Crypt::NaCl::Sodium;
use Crypt::Random qw( makerandom_octet );
use Digest::MD5;
use Digest::SHA;
use Mcrypt qw(ARCFOUR RIJNDAEL_128 RIJNDAEL_192 RIJNDAEL_256);
use Mcrypt qw(:MODES);
use Mcrypt qw(:FUNCS);

our $VERSION = '0.8.1';

our %_ciphers = 
    (
        "rc4-md5"  => [Mcrypt::ARCFOUR,Mcrypt::STREAM,16,16],
        "rc4-sha" => [Mcrypt::ARCFOUR,Mcrypt::STREAM,16,20],
        "aes-128-cbc"  => [Mcrypt::RIJNDAEL_128,Mcrypt::CBC,16,16],
        "aes-128-cfb"  => ['AES','cfb',16,16],
        "aes-128-ctr"  => ['AES','ctr',16,16],
        "aes-128-ofb" => [Mcrypt::RIJNDAEL_128,Mcrypt::OFB,16,16],
        "aes-192-cbc"  => [Mcrypt::RIJNDAEL_192,Mcrypt::CBC,24,16],     
        "aes-192-cfb" => ['AES','cfb',24,16],
        "aes-192-ctr"  => ['AES','ctr',24,16],
        "aes-192-ofb" => [Mcrypt::RIJNDAEL_192,Mcrypt::OFB,24,16],
        "aes-256-cbc"  => [Mcrypt::RIJNDAEL_256,Mcrypt::CBC,32,16],
        "aes-256-cfb"  => ['AES','cfb',32,16],
        "aes-256-ctr"  => ['AES','ctr',32,16],
        "aes-256-ofb"  => [Mcrypt::RIJNDAEL_256,Mcrypt::OFB,32,16],
        "camellia-128-cbc" => ['Camellia','cbc',16,16],
        "camellia-128-cfb" => ['Camellia','cfb',16,16],
        "camellia-128-ctr" => ['Camellia','ctr',16,16],
        "camellia-128-ofb" => ['Camellia','ofb',16,16],
        "camellia-192-cbc" => ['Camellia','cbc',24,16],
        "camellia-192-cfb" => ['Camellia','cfb',24,16],
        "camellia-192-ctr" => ['Camellia','ctr',24,16],
        "camellia-192-ofb" => ['Camellia','ofb',24,16],
        "camellia-256-cbc" => ['Camellia','cbc',32,16],
        "camellia-256-cfb" => ['Camellia','cfb',32,16],
        "camellia-256-ctr" => ['Camellia','ctr',32,16],
        "camellia-256-ofb" => ['Camellia','ofb',32,16],
        "chacha20-ietf" => [undef,undef,32,12],
        "rc6" => [undef,undef,8,16]
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
    my $_iv;
    my $_nonce;
    if (!defined($_method))
    {
        AE::log info => "Encryption method undefinde, using RC4-MD5." ;
        $_encryptor = Mcrypt::mcrypt_load(Mcrypt::ARCFOUR,'',Mcrypt::STREAM , '' );
        $_decryptor = Mcrypt::mcrypt_load(Mcrypt::ARCFOUR ,'',Mcrypt::STREAM, '' );
        $_key = _EVP_BytesToKey(16, 16, '', $_password, 1 );
        $_iv = makerandom_octet( Length => 16 );
        my $md = Digest::MD5->new();
        $md->add($_key . $_iv);
        my $encrypt_rc4_key = $md->digest();
        Mcrypt::mcrypt_init($_encryptor, $encrypt_rc4_key, '' );      
        }
        else
        {
            if($_method eq 'chacha20-ietf')
            {
                $_encryptor = Crypt::NaCl::Sodium->stream();
                $_key = $_encryptor->chacha20_keygen();
                $_nonce = $_encryptor->chacha20_ietf_nonce();
                $_decryptor = Crypt::NaCl::Sodium->stream();
                $_iv = $_nonce;
                }
            elsif ( $_method eq 'rc6') 
            {
                $_key = _EVP_BytesToKey($_ciphers{$_method}->[2], $_ciphers{$_method}->[3] , '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] );
                $_encryptor = Crypt::Mode::CBC->new('RC6');
                $_decryptor = Crypt::Mode::CBC->new('RC6');
            }
            elsif(defined($_method) and $_method =~ /cfb$/)
            {
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] ); 
                $_encryptor = Crypt::Mode::CFB->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::CFB->new($_ciphers{$_method}->[0]);
            }
             elsif(defined($_method) and $_method =~ /ctr$/)
            {
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] ); 
                $_encryptor = Crypt::Mode::CTR->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::CTR->new($_ciphers{$_method}->[0]);
            }
             elsif(defined($_method) and $_method =~ /^camellia/)
            {
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] );
                if ($_method =~ /cbc$/)
                { 
                $_encryptor = Crypt::Mode::CBC->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::CBC->new($_ciphers{$_method}->[0]);
                }
                elsif($_method =~ /cfb$/)
                {
                $_encryptor = Crypt::Mode::CFB->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::CFB->new($_ciphers{$_method}->[0]);
                }
                elsif($_method =~ /ctr$/)
                {
                $_encryptor = Crypt::Mode::CTR->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::CTR->new($_ciphers{$_method}->[0]);
                }
                elsif($_method =~ /ofb$/)
                {
                $_encryptor = Crypt::Mode::OFB->new($_ciphers{$_method}->[0]);
                $_decryptor = Crypt::Mode::OFB->new($_ciphers{$_method}->[0]);
                }
            }
            elsif(defined($_method) and $_method !~ /cfb$/ and $_method !~ /ctr$/  and $_method !~ /^camellia/)
            {
                $_encryptor = Mcrypt::mcrypt_load($_ciphers{$_method}->[0],'',$_ciphers{$_method}->[1] , '' );
                $_decryptor = Mcrypt::mcrypt_load($_ciphers{$_method}->[0] ,'',$_ciphers{$_method}->[1], '' );
                $_key = _EVP_BytesToKey( $_ciphers{$_method}->[2], $_ciphers{$_method}->[3], '', $_password, 1 );
                $_iv = makerandom_octet( Length => $_ciphers{$_method}->[3] );
                if ($_method eq 'rc4-md5' )
                {
                   my $md = Digest::MD5->new();
                   $md->add($_key . $_iv);
                   my $encrypt_rc4_key = $md->digest();
                   Mcrypt::mcrypt_init($_encryptor, $encrypt_rc4_key, '' );
                }
                elsif($_method eq 'rc4-sha' )
                {
                   my $sha = Digest::SHA->new();
                   $sha->add($_key . $_iv);
                   my $encrypt_rc4_key = substr($sha->digest(),0,16);
                   Mcrypt::mcrypt_init($_encryptor, $encrypt_rc4_key, '' );
                }
                elsif($_method ne 'rc6')
                {
                   Mcrypt::mcrypt_init($_encryptor, $_key, $_iv );
                }
           }
    }
    return $_encryptor, $_decryptor, $_key, $_iv, $_nonce;
}

sub _get_algorithm($)
{
    my $_method   = shift;
    return $_ciphers{$_method}->[0];
    }

sub _get_mode($)
{
    my $_method   = shift;
    return $_ciphers{$_method}->[1];
    }

1;    # End of Net::Shadowsocks

 __END__

=pod

=encoding utf8

=head1 NAME

Net::Shadowsocks

=head1 VERSION

Version 0.8.1

=head1 SYNOPSIS

    ssclient.pl is the asynchronous, non-blocking shadowsocks client. 
    ssserver.pl is the asynchronous, non-blocking shadowsocks server. 
    Run ssclient.pl and/or ssserver.pl and follow instructions.
    
=head1 DESCRIPTION

Net::Shadowsocks is a Perl implementation of the shadowsocks (Chinese: 影梭)
protocol client and server , Shadowsocks is a secure transport protocol based on
SOCKS Protocol Version 5 (RFC 1928 ). 

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

