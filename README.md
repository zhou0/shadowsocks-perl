# NAME

Net::Shadowsocks - the asynchronous, non-blocking shadowsocks client and server. 

[![Build Status](https://travis-ci.org/zhou0/shadowsocks-perl.png?branch=master)](https://travis-ci.org/zhou0/shadowsocks-perl)

# VERSION

Version 0.9.1

# SYNOPSIS

# DESCRIPTION

Shadowsocks is a secure transport protocol based on SOCKS Protocol Version 5 (RFC 1928 ).Net::Shadowsocks is a Perl implementation of the shadowsocks (Chinese: 影梭) protocol client and server. ssclient.pl is the asynchronous, non-blocking shadowsocks client. ssserver.pl is the asynchronous, non-blocking shadowsocks server. Run ssclient.pl and/or ssserver.pl and follow instructions.

1\. A total of 34 encryption methods are supported:

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

# SEE ALSO

[Shadowsocks Official website ](https://shadowsocks.org/en/index.html),[Shadowsocks on Wikipedia ](https://en.wikipedia.org/wiki/Shadowsocks)

# AUTHOR

Li ZHOU, `<lzh at cpan.org>`

# BUGS

Please report any bugs or feature requests to `bug-net-shadowsocks at rt.cpan.org`, or through
the web interface at [http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Shadowsocks](http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-Shadowsocks).  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

# SUPPORT

You can find documentation for this module with the perldoc command.

perldoc Net::Shadowsocks

You can also look for information at:

- RT: CPAN's request tracker (report bugs here)

    [http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Shadowsocks](http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-Shadowsocks)

- AnnoCPAN: Annotated CPAN documentation

    [http://annocpan.org/dist/Net-Shadowsocks](http://annocpan.org/dist/Net-Shadowsocks)

- CPAN Ratings

    [http://cpanratings.perl.org/d/Net-Shadowsocks](http://cpanratings.perl.org/d/Net-Shadowsocks)

- Search CPAN

    [http://search.cpan.org/dist/Net-Shadowsocks/](http://search.cpan.org/dist/Net-Shadowsocks/)

# ACKNOWLEDGEMENTS

# LICENSE AND COPYRIGHT

Copyright 2017 Li ZHOU.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

[http://www.perlfoundation.org/artistic\_license\_2\_0](http://www.perlfoundation.org/artistic_license_2_0)

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
