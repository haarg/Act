package Act::Handler::AuthMethods;

use strict;
use warnings;
use parent 'Act::Handler';

use Act::AuthMethods;
use Act::Config;
use Act::Template::HTML;
use Act::Util;

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

    $session->{'auth_method'} = $auth_method->name;
    my $user_id = $auth_method->handle_postback($r);

    if(defined $user_id) {
        my $res  = $r->response;
        my $user = Act:User->new( user_id => $user_id ) or die ["Unknown user"];
        my $sid  = Act::Util::create_session($user);
        # XXX use Act::MW::Auth's _set_session?
        $res->cookies->{'Act_session_id'} = {
            value => $sid,
        };
        return $res->finalize;
    } else {
        my $template = Act::Template::HTML->new;
        $template->process('associate_auth_method');
        return 200;
    }
        my $template = Act::Template::HTML->new;
        $template->process('associate_auth_method');
        return 200;
}

1;

__END__

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 FUNCTIONS

=cut
