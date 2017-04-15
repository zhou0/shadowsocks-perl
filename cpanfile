requires "AnyEvent" => "4.45";
requires "AnyEvent::Handle" => "0";
requires "AnyEvent::Log" => "0";
requires "AnyEvent::Socket" => "0";
requires "Carp" => "0";
requires "Crypt::AuthEnc::GCM" => "0";
requires "Crypt::Cipher::AES" => "0";
requires "Crypt::Cipher::Camellia" => "0";
requires "Crypt::Cipher::RC6" => "0";
requires "Crypt::HC128" => "0";
requires "Crypt::KeyDerivation" => "0";
requires "Crypt::Mode::CFB" => "0";
requires "Crypt::Mode::CTR" => "0";
requires "Crypt::Mode::OFB" => "0";
requires "Crypt::PRNG" => "0";
requires "Crypt::RC4::XS" => "0";
requires "Crypt::Spritz" => "1.02";
requires "Digest::MD5" => "2.55";
requires "Getopt::Std" => "0";
requires "IO::Socket::Socks" => "0.73";
requires "JSON" => "2.90";
requires "Socket" => "2.021";
requires "perl" => "5.006";
requires "strict" => "0";
requires "warnings" => "0";

on 'build' => sub {
  requires "Module::Build" => "0.28";
};

on 'test' => sub {
  requires "ExtUtils::MakeMaker" => "6.3";
  requires "File::Spec" => "0";
  requires "IO::Handle" => "0";
  requires "IPC::Open3" => "0";
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Test::CPAN::Meta" => "0";
  requires "Test::CheckDeps" => "0.010";
  requires "Test::More" => "0.94";
  requires "Test::Pod::Coverage" => "0";
  requires "blib" => "1.01";
};

on 'test' => sub {
  recommends "CPAN::Meta" => "2.120900";
};

on 'configure' => sub {
  requires "ExtUtils::MakeMaker" => "0";
  requires "Module::Build" => "0.28";
};

on 'develop' => sub {
  requires "File::Spec" => "0";
  requires "IO::Handle" => "0";
  requires "IPC::Open3" => "0";
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Test::CPAN::Meta" => "0";
  requires "Test::CPAN::Meta::JSON" => "0.16";
  requires "Test::Kwalitee" => "1.21";
  requires "Test::Mojibake" => "0";
  requires "Test::More" => "0.88";
  requires "Test::NoTabs" => "0";
  requires "Test::Pod" => "1.41";
  requires "Test::Pod::Coverage" => "1.08";
  requires "Test::Portability::Files" => "0";
  requires "Test::Synopsis" => "0";
  requires "blib" => "1.01";
};
