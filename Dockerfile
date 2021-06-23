FROM perl:5.22
ARG VCS_REF
LABEL org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/zhou0/shadowsocks-perl"
MAINTAINER  Li ZHOU lzh@cpan.org
RUN cpan -T AnyEvent::AIO Crypt::NaCl::Sodium EV IO::AIO Net::Shadowsocks
EXPOSE 1491
CMD ssserver.pl -s localhost -p 1491 -k fuckgfw -m chacha20-ietf
