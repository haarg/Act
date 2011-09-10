package Act::AuthMethod::Facebook;

use strict;
use warnings;
use parent 'Act::AuthMethod';

use Act::Config;
use Act::Util qw(make_uri);

sub new {
    my ( $class ) = @_;

    my $load_ok = eval {
        require Facebook::Graph;
        1;
    };
    return unless $load_ok;

    my $app_id = $Config->facebook_app_id;
    my $secret  = $Config->facebook_secret;

    return unless defined($app_id) && defined($secret);

    my $self           = Act::AuthMethod::new($class);
    $self->{'app_id'} = $app_id;
    $self->{'secret'}  = $secret;

    return $self;
}

sub app_id {
    my ( $self ) = @_;

    return $self->{'app_id'};
}

sub secret {
    my ( $self ) = @_;

    return $self->{'secret'};
}

sub facebook_graph {
    my ( $self ) = @_;

    return Facebook::Graph->new(
        app_id   => $self->app_id,
        secret   => $self->secret,
        postback => make_uri('auth_methods/facebook'),
    );
}

# XXX we have to be *really* careful about XSS possibilities
sub render {
    my ( $self ) = @_;

    my $fb  = $self->facebook_graph;
    my $uri = $fb->authorize->uri_as_string;

    ## i18nize
    return <<HTML;
<a href='$uri' class='fb_button fb_button_medium'>
  <span class='fb_button_text'>Log In With Facebook</span>
</a>
HTML
}

sub name {
    return 'facebook';
}

sub handle_postback {
    my ( $self ) = @_;

    my $fb = $self->facebook_graph;
    $fb->request_access_token($params->{'code'});
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
