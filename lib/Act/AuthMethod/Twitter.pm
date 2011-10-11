package Act::AuthMethod::Twitter;

use strict;
use warnings;
use parent 'Act::AuthMethod';

use Act::Config;
use Act::Util qw(localize make_abs_uri);

sub new {
    my ( $class ) = @_;

    my $load_ok = eval {
        require Net::Twitter;
        1;
    };
    return unless $load_ok;

    my $consumer_key    = $Config->twitter_consumer_key;
    my $consumer_secret = $Config->twitter_consumer_secret;

    return unless defined($consumer_key) && defined($consumer_secret);

    my $self    = Act::AuthMethod::new($class);
    unless($twitter) {
        $twitter = Net::Twitter->new(
            traits          => [qw/OAuth API::REST/],
            consumer_key    => $consumer_key,
            consumer_secret => $consumer_secret,
        );
    }

    my $callback_url       = make_abs_uri('auth_methods/twitter');
    $self->{'twitter_url'} = $twitter->get_authorization_url(
        callback => $callback_url);

    #$Request{r}->session->{'net_twitter'} = $twitter;

    return $self;
}

sub render {
    my ( $self ) = @_;

    #my $uri        = $self->{'twitter_url'};
    my $uri        = 'http://localhost:5000';
    my $login_text = localize('Login with Twitter');

    return <<HTML;
<a href='$uri'>$login_text</a>
HTML
}

sub name {
    return 'twitter';
}

sub handle_postback {
    my ( $self, $req ) = @_;

    my $twitter = $Request{r}->session->{'net_twitter'};

    use Data::Dumper::Concise;
    print STDERR Dumper($req->env);
}

sub associate_with_user {
    my ( $self, $req, $user ) = @_;
}

1;

__END__

=head1 NAME

Act::AuthMethod::Twitter - Twitter authentication integration for Act

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 FUNCTIONS

=head1 SEE ALSO

L<Act::AuthMethod>

=cut
