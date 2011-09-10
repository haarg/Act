package Act::Handler::AuthMethods;

use strict;
use warnings;
use parent 'Act::Handler';

use Act::AuthMethods;
use Act::Config;

sub handler
{
    my $r           = $Request{r};
    my $auth_method = $r->path_info;

    $auth_method =~ s!^/!!;
    $auth_method =~ s!/.*!!;

    my $methods = Act::AuthMethods->retrieve;
    foreach my $method (@$methods) {
        if($auth_method eq $method->name) {
            $auth_method = $method;
            last;
        }
    }
    unless(ref $auth_method) {
        return [
            404,
            ['Content-Type' => 'text/html'],
            # XXX i18ize
            ['<html><body>No such auth method</body></html>'], 
        ];
    }

    $auth_method->handle_postback($r);
    
    return 200;

}

1;

__END__

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 FUNCTIONS

=cut
