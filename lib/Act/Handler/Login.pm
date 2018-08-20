package Act::Handler::Login;

use strict;
use Apache::Constants qw(DONE);
use Act::Config;
use Act::Template::HTML;
use Act::Util;

sub handler
{
    my $r = $Request{r};

    # disable client-side caching
    $r->no_cache(1);

    # destination URI
    my $uri = $env->{'act.login.destination'} || Act::Util::make_uri('');

    # process the login form template
    my $template = Act::Template::HTML->new();
    $template->variables(
        error       => $env->{'act.login.error'},
        destination => $uri,
        action      => join('/', '', $Request{conference}, 'LOGIN'),
        domain      => join('.', (split /\./, $r->env->{SERVER_NAME})[-2, -1]),
    );
    $template->process('login');
    $Request{status} = 200;
}
1;
__END__

=head1 NAME

Act::Handler::Login - display the login form

=head1 DESCRIPTION

This is automatically called by Act::Auth when access to
the requested page requires authentication.

=cut
