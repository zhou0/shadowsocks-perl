SYNOPSIS
 
    Shadowsocks protocol client and server module.
     
DESCRIPTION
 
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
