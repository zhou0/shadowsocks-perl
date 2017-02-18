requires "AnyEvent" => "4.45";
requires "AnyEvent::Handle" => "0";
requires "AnyEvent::Log" => "0";
requires "AnyEvent::Socket" => "0";
requires "Carp" => "0";
requires "Crypt::Cipher::AES" => "0";
requires "Crypt::Cipher::Camellia" => "0";
requires "Crypt::Cipher::RC6" => "0";
requires "Crypt::Mode::CBC" => "0";
requires "Crypt::Mode::CFB" => "0";
requires "Crypt::Mode::CTR" => "0";
requires "Crypt::Mode::OFB" => "0";
requires "Crypt::NaCl::Sodium" => "v1.0.8.0";
requires "Crypt::Random" => "1.25";
requires "Digest::MD5" => "2.55";
requires "Digest::SHA" => "5.96";
requires "Getopt::Std" => "0";
requires "IO::Socket::Socks" => "0.73";
requires "JSON" => "2.90";
requires "Mcrypt" => "v2.5.7.0";
requires "Socket" => "2.021";
requires "perl" => "5.006";
requires "strict" => "0";
requires "warnings" => "0";

on 'build' => sub {
  requires "Module::Build" => "0.28";
};

on 'test' => sub {
  requires "ExtUtils::MakeMaker" => "0";
  requires "File::Spec" => "0";
  requires "IO::Handle" => "0";
  requires "IPC::Open3" => "0";
  requires "Test::CheckDeps" => "0.010";
  requires "Test::More" => "0.94";
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
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Test::MinimumVersion" => "0";
  requires "Test::More" => "0";
  requires "Test::Pod" => "1.41";
  requires "Test::Pod::Coverage" => "1.08";
  requires "Test::Spelling" => "0.12";
};
