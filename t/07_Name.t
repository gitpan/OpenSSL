
use Test;
BEGIN { plan tests => 3 };
use OpenSSL::Name;
ok(1);

$n = new OpenSSL::Name;

$n->add('Email', '<stefan@hello-penguin.com>');
$n->add('Email', "<stefan$_\@hello-penguin.com>") for (1..10);
ok(1);

$n->add(47, 'oesi@plan9.de');
ok(1);
