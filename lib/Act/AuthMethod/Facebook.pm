package Act::AuthMethod::Facebook;

use strict;
use warnings;
use parent 'Act::AuthMethod';

use Act::Config;
use Act::Util qw(localize make_uri);

sub new {
    my ( $class ) = @_;

    my $load_ok = eval {
        require Facebook::Graph;
        1;
    };
    return unless $load_ok;

    my $app_id = $Config->facebook_app_id;
    my $secret = $Config->facebook_secret;

    return unless defined($app_id) && defined($secret);

    my $self = Act::AuthMethod::new($class);
    my $fb   = $Request{r}->session->{'facebook_graph'};
    unless($fb) {
        $fb = Facebook::Graph->new(
            app_id   => $app_id,
            secret   => $secret,
            postback => make_uri('auth_methods/facebook'),
            ## deregister URL
        );
    }

    $self->{'facebook_uri'} = $fb->authorize->uri_as_string;

    $Request{r}->session->{'facebook_graph'} = $fb;

    return $self;
}

# XXX we have to be *really* careful about XSS possibilities
sub render {
    my ( $self ) = @_;

    my $uri        = $self->{'facebook_uri'};
    my $login_text = localize('Login with Facebook');

    ## i18nize
    return <<HTML;
<a href='$uri' class='fb_button fb_button_medium'>
  <span class='fb_button_text'>$login_text</span>
</a>
HTML
}

sub name {
    return 'facebook';
}

sub handle_postback {
    my ( $self, $req ) = @_;

    my $fb   = $Request{r}->session->{'facebook_graph'};
    my $code = $req->param('code');

    $fb->request_access_token($code);
    
    use Data::Dumper::Concise;

    $req->response->content_type('text/plain');
    $req->response->body(Dumper($fb->fetch('me')));
    ## create new user
}


1;

__END__

=head1 NAME

Act::AuthMethod::Facebook - Facebook authentication integration for Act

=head1 DESCRIPTION

=head1 METHODS

=head1 SEE ALSO

L<Act::AuthMethod>

=cut
