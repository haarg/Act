use Test::More tests => 11;
use strict;
use t::Util;
use Act::Talk;
use Act::User;

# load some users
db_add_users();

my $user  = Act::User->new( login => 'book' );
my $user2 = Act::User->new( login => 'echo' );
my ( $talks, $talk, $talk1, $talk2, $talk3 );

# manually insert a talk
my $sth = $Request{dbh}->prepare_cached("INSERT INTO talks (user_id,conf_id,duration,lightning,accepted,confirmed) VALUES(?,?,?,?,?,?);");
$sth->execute( $user->user_id, 'conf', 12, 'f', 'f', 'f' );
$sth->finish();

$sth = $Request{dbh}->prepare_cached("SELECT * from talks WHERE user_id=?");
$sth->execute( $user->user_id);
my $hash = $sth->fetchrow_hashref;
$sth->finish;

$talk1 = Act::Talk->new( talk_id => $hash->{talk_id} );
isa_ok( $talk1, 'Act::Talk' );
is_deeply( $talk1, $hash, "Can insert a talk" );

$talk = Act::Talk->new();
isa_ok( $talk, 'Act::Talk' );
is_deeply( $talk, {}, "create empty talk with new()" );

# create a talk
$talk2 = Act::Talk->create(
   title     => 'test',
   user_id   => $user2->user_id,
   conf_id   => 'conf',
   duration  => 5,
   lightning => 'true',
   accepted  => '0',
   confirmed => 'false',
);
isa_ok( $talk2, 'Act::Talk' );

# check the talk value (it works because $user2 has only one talk)
is_deeply( Act::Talk->new( user_id => $user2->user_id ),
   {
   talk_id      => $talk2->talk_id,
   user_id      => $user2->user_id,
   title        => 'test',
   conf_id      => 'conf',
   duration     => 5,
   given        => undef,
   url_talk     => undef,
   url_abstract => undef,
   abstract     => undef,
   room         => undef,
   comment      => undef,
   # boolean values
   lightning    => 1,
   accepted     => 0,
   confirmed    => 0,
   },
  "User 2's talk" );

# talks are sorted by ids, which are incremental
$talks = $user->talks;
is_deeply( $talks, [ $talk1 ], "Got the user's talk" );

# add another talk
$talk3 = Act::Talk->create(
   title     => 'test 2',
   user_id   => $user->user_id,
   conf_id   => 'conf',
   duration  => 40,
   lightning => 'FALSE',
   accepted  => 'F',
   confirmed => 'F',
);

# search method
$talks = Act::Talk->get_talks( duration => 40 );
is_deeply( $talks, [ $talk3 ], "40 minute talks" );
$talks = Act::Talk->get_talks( lightning => 'TRUE' );
is_deeply( $talks, [ $talk2 ], "lightning talks" );
$talks = Act::Talk->get_talks( user_id => $user->user_id );
is_deeply( $talks, [ $talk1, $talk3 ], "Got the user's talks" );

# this a Act::User method that encapsulate get_talks
$talks = $user->talks;
is_deeply( $talks, [ $talk1, $talk3 ], "Got the user's talks" );

