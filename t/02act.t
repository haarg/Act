#!perl -w
use strict;
use Test::More;
use File::Find;

my @modules;

find( sub {
          return unless /\.pm$/; local $_ = $File::Find::name;
          s!^lib/!!; s!/!::!g; s/\.pm$//;
          push @modules, $_;
      }, 'lib/Act' );

plan tests => scalar(@modules);

require_ok($_) for @modules;
