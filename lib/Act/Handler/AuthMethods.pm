package Act::Handler::AuthMethods;

use strict;
use warnings;
use parent 'Act::Handler';

use Act::AuthMethods;
use Act::Config;
use Act::Template::HTML;
use Act::Util qw(make_uri);
use Try::Tiny;

sub handler
{
    my $r           = $Request{r};
    my $auth_method = $r->path_info;
    my $session     = $r->session;

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

    if($r->method eq 'GET') {
        $session->{'auth_method'} = $auth_method->name;
        my $user_id = $auth_method->handle_postback($r);

        if(defined $user_id) {
            my $res  = $r->response;
            my $user = Act::User->new( user_id => $user_id ) or die ["Unknown user"];
            my $sid  = Act::Util::create_session($user);
            Act::Middleware::Auth::_set_session($res, $sid, 0);
            my $url = '/' . $r->env->{'act.conference'} . '/';
            $res->redirect($url);
            return $res->status;
        } else {
            my $template = Act::Template::HTML->new;
            $template->process('associate_auth_method');
            return;
        }
    } else {
         my $params = $r->parameters;

         if($params->{'skip'}) {
            my $template = Act::Template::HTML->new;
            $template->variables(
                countries => Act::Country::CountryNames(),
                topten    => Act::Country::TopTen(),
                end_date => DateTime::Format::Pg->parse_timestamp($Config->talks_end_date)->epoch,
            );
            $template->process('user/add');
            return;
        } elsif($params->{'join'}) {
            my $res  = $r->response;

            my $passwd = Act::Util::gen_password();

            my %fields = (
                password      => $passwd,
                participation => {
                    tshirt_size => $params->{tshirt},
                    datetime    => DateTime::Format::Pg->format_timestamp_without_time_zone(DateTime->now()),
                    ip          => $r->address,
                },
            	timezone => $Config->general_timezone,
                map { $_ => $params->{$_} } qw(login first_name last_name email country),
            );
            my $user = Act::User->create(%fields);
            $auth_method->associate_with_user($r, $user);
            my $sid  = Act::Util::create_session($user);
            Act::Middleware::Auth::_set_session($res, $sid, 0);
            my $url = '/' . $r->env->{'act.conference'} . '/';
            $res->redirect($url);
            return $res->status;
         } else {
            my $username = $params->{'username'};
            my $password = $params->{'password'};

            my $user = Act::User->new( login => $username );
            unless($user) {
                my $template = Act::Template::HTML->new;
                $template->variables(
                    error => 'Unknown user',
                );
                $template->process('associate_auth_method');
                return;
            }

            try {
                $user->check_password($password);

                $auth_method->associate_with_user($r, $user);
                my $sid = Act::Util::create_session($user);
                my $res = $r->response;
                Act::Middleware::Auth::_set_session($res, $sid, 0);
                my $url = '/' . $r->env->{'act.conference'} . '/';
                $res->redirect($url);
            } catch {
                my $template = Act::Template::HTML->new;
                $template->variables(
                    error => 'Bad password',
                );
                $template->process('associate_auth_method');
            };
            return;
         }
    }
}

1;

__END__

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 FUNCTIONS

=cut
