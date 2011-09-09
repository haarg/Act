package Act::AuthMethods;

use strict;
use warnings;

use Module::Find;

sub retrieve {
    my @methods = usesub Act::AuthMethod;

    @methods = grep {
        defined()
    } map {
        $_->new
    } @methods;

    return \@methods;
}

1;

__END__

=head1 NAME

Act::AuthMethods - Manager class for Act auth methods.

=head1 SYNOPSIS

  use Act::AuthMethods;

  my $methods = Act::AuthMethods->retrieve;

=head1 DESCRIPTION

A simple little utility class for retrieving the auth methods
available.

=head1 METHODS

=head2 retrieve

Returns an array reference containing the auth methods available
to this instance of Act.

=cut
