FROM perl:5.22
MAINTAINER  Li ZHOU lzh@cpan.org
RUN apt-get update && apt-get install -y libtomcrypt-dev unzip
RUN cpan Crypt::NaCl::Sodium EV IO::AIO Net::Shadowsocks
EXPOSE 1895
CMD ssserver.pl -s localhost -p 1895 -k diegfwdie -m spritz
