# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 10' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 13 };
use OpenSSL::Digest qw(digest_hex sha1_hex new_digest);
ok(1);
         
ok((OpenSSL::Digest::sha1_hex("hallo\n") eq  '56ac1c08fa5479fd57c4a5c65861c4ed3ed93ff8') ? 1 :0);
ok((sha1_hex("hallo\n") eq  '56ac1c08fa5479fd57c4a5c65861c4ed3ed93ff8') ? 1 :0);
ok((OpenSSL::Digest::md5_hex("hallo\n") eq  'aee97cb3ad288ef0add6c6b5b5fae48a') ? 1 :0);
ok((OpenSSL::Digest::md2_hex("hallo\n") eq  '0b5a59754c4ba601ff1234aba049fd0b') ? 1 :0);
ok((OpenSSL::Digest::md4_hex("hallo\n") eq  'bf3d4821a7c02a3bfa9a423c057fc761') ? 1 :0);
ok((OpenSSL::Digest::sha_hex("hallo\n") eq  '76b9078ec3698799870bfee2ac7f803dd0dc8ad2') ? 1 :0);
ok((OpenSSL::Digest::mdc2_hex("hallo\n") eq  '17893a33039f9273b0d15d9c97c2073c') ? 1 :0);
ok((OpenSSL::Digest::ripemd160_hex("hallo\n") eq  '84950d43051dee712a1de55f13e2cf250ad9ace4') ? 1 :0);
ok((digest_hex('sha1', 'ha', "llo\n") eq '56ac1c08fa5479fd57c4a5c65861c4ed3ed93ff8') ? 1 :0);
ok((digest_hex('sha1', '') eq 'da39a3ee5e6b4b0d3255bfef95601890afd80709') ? 1 :0);
ok((digest_hex('sha1') eq 'da39a3ee5e6b4b0d3255bfef95601890afd80709') ? 1 :0);

$ctx = new_digest('sha1');
$ctx->update('h');
$ctx->update("allo\n");
ok(($ctx->final_hex eq '56ac1c08fa5479fd57c4a5c65861c4ed3ed93ff8') ? 1 :0);
