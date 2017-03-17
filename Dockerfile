FROM perl:5.22
MAINTAINER  Li ZHOU lzh@cpan.org
RUN apt-get update && apt-get install -y libtomcrypt-dev
RUN cpan Archive::Zip  Crypt::NaCl::Sodium EV Net::Shadowsocks
EXPOSE 1895
CMD ssserver.pl -s localhost -p 1895 -k diegfwdie -m spritz
