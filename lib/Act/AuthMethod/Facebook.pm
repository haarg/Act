package Act::AuthMethod::Facebook;

use strict;
use warnings;
use parent 'Act::AuthMethod';

use Act::Config;

sub new {
    my ( $class ) = @_;

    my $load_ok = eval {
        require Facebook::Graph;
        1;
    };
    return unless $load_ok;

    my $api_key = $Config->facebook_api_key;
    my $secret  = $Config->facebook_secret;

    return unless defined($api_key) && defined($secret);

    my $self           = Act::AuthMethod::new($class);
    $self->{'api_key'} = $api_key;
    $self->{'secret'}  = $secret;

    return $self;
}

sub api_key {
    my ( $self ) = @_;

    return $self->{'api_key'};
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
        postback => 'http://localhost:5000/yapcna/auth_methods/facebook',
    );
}

sub render {
    my ( $self ) = @_;

    my $fb  = $self->facebook_graph;
    my $uri = $fb->authorize->uri_as_string;

    ## fill in image source
    ## i18nize
    return <<HTML;
<a href='$uri'><img src='' alt='Login with Facebook'/></a>
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