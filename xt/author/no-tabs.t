use strict;
use warnings;

# this test was generated with Dist::Zilla::Plugin::Test::NoTabs 0.15

use Test::More 0.88;
use Test::NoTabs;

my @files = (
    'bin/ssclient.pl',
    'bin/ssserver.pl',
    'lib/Net/Shadowsocks.pm',
    'lib/Net/Shadowsocks/Client.pm',
    'lib/Net/Shadowsocks/Server.pm',
    't/00-check-deps.t',
    't/00-compile.t',
    't/00-report-prereqs.dd',
    't/00-report-prereqs.t'
);

notabs_ok($_) foreach @files;
done_testing;
