package Act::Template::HTML;

use strict;
use HTML::Entities;
use Template::Constants qw(CHOMP_COLLAPSE);
use base 'Act::Template';

use Act::Config;

my %filters = (
    form_unescape  => sub { (my $x = $_[0]) =~ s/&quot;/"/g; $x },   # "
);

sub _init
{
    my ($self, $options) = @_;

    $options->{FILTERS} ||= {};
    @{$options->{FILTERS}}{keys %filters} = values %filters;

    for (qw(PRE_CHOMP POST_CHOMP)) {
        $options->{$_} = CHOMP_COLLAPSE
            unless defined $options->{$_};
    }
    $self->SUPER::_init($options);
}

sub escape
{
    # recursively escape HTML entities
    my $self = shift;

    if (ref $_[0] eq 'DateTime') {
        return $_[0];
    }
    if ($_[0] && UNIVERSAL::isa($_[0],'ARRAY')) {
        $self->escape($_) for @{$_[0]};
    }
    elsif ($_[0] && UNIVERSAL::isa($_[0],'HASH')) {
        $self->escape($_[0]{$_}) for keys %{$_[0]};
    }
    elsif (ref $_[0]) {
        return $_[0];
    }
    elsif (defined $_[0]) {
        return HTML::Entities::encode($_[0], '<>&"');
    }
    return $_[0];
}

sub variables_raw
{
    my $self = shift;
    {
        no warnings 'redefine';
        local *escape = sub { $_[1] };
        $self->variables(@_);
    }
}

sub process
{
    my $self = shift;

    # set Content-Type and send HTTP headers if not already done
    my $r = $Request{r};
    if ($r && ref($r) && $r->isa('Act::Request') && !$Request{sent_http_header}++) {
        $r->send_http_header('text/html; charset=UTF-8');
    }
    return $self->SUPER::process(@_);
}

1;

__END__

=head1 NAME

Act::Template::HTML - an HTML template object class

=head1 SYNOPSIS

    use Act::Template::HTML;
    my $template = Act::Template::HTML->new();
    $template->variables(foo => 42);
    $template->process('talkview');

=head1 DESCRIPTION

The Act::Template::HTML class is used to process Act templates that contain
HTML text.

=head2 Methods

Act::Template::HTML inherits from Act::Template, and adds or overrides the
following methods:

=over 4

=item variables(I<%variables>)

Set template variables. Does a recursive scan of the variable values
and escapes all HTML characters (&, E<lt> and E<gt> are converted to
HTML entities).

=item variables_raw(I<%variables>)

Set template variables without escaping. This is useful when a variable
value holds an already properly formatted HTML or XML snippet.

=item process(I<$template_name>, I<$output>)

This will set the response's Content-Type and send the HTTP headers
if necessary when used in a mod_perl context.

=back

=cut
