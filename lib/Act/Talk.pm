package Act::Talk;
use Act::Config;

=head1 NAME

Act::Talk - A talk object

=head1 SYNOPSIS

    $talk = Act::Talk->new( $id );

=head1 DESCRIPTION

=head2 Methods

The Act::Talk class implements the following methods:

=over 4

=item new( $id )

The constructor returns an existing Act::Talk object, given a talk id.
name. If no user by this name exists, return C<undef>.

=cut

sub new {
    my ( $class, $id ) = @_;

    my $sth = $Request{dbh}->prepare_cached('SELECT * FROM talks WHERE conf_id=? talk_id=?');
    $sth->execute($Request{conference}, $id);
    my $self = $sth->fetchrow_hashref();
    $sth->finish;

    return undef unless $self;

    bless $self, $class;
}

=item accessors

All the accessors give read access to the data held in the users table.
The accessors are autoloaded.

=cut

sub AUTOLOAD {
    # don't DESTROY
    return if $AUTOLOAD =~ /::DESTROY/;

    # get the talk attributes
    if( $AUTOLOAD =~  /::(\w+)$/ and exists $_[0]->{$1} ) {
        my $attr = $1;
        if ( $attr eq lc $attr ) {
            no strict 'refs';
    
            # create the method and call it
            *{$AUTOLOAD} = sub { $_[0]->{$attr} };
            goto &{$AUTOLOAD};
        }
    }

    # should we croak? carp? do something?
}

=back

=head2 Class methods

Act::Talk also defines the following class methods:

=over 4

=item get_talks( %req )

Return a reference to an array of Act::Talk objects matching the request
parameters.

    $users = Act::Talk->get_talks( user_id => 132, conf => '2004' );

Acceptable parameter are: C<conf>, C<user>, C<title>, C<abstract>,
C<>,
C<duration>, C<room>, C<lightning>, C<accepted> and C<confirmed>.
The C<limit> and C<offset> options can be given to limit
the number of results. All other parameters are ignored.

=cut

sub get_talks {
    my ( $class, %args ) = @_;
    $class = ref $class  || $class;

    # search field to SQL mapping
    my %req = (
        conf      => "(conf_id=?)",
        user      => "(user_id=?)",
        title     => "(title~*?)",
        abstract  => "(abstract~*?)",
        duration  => "(duration=?)",
        room      => "(room=?)",
        lightning => "(lightning IS TRUE)",
        accepted  => "(accepted IS TRUE)",
        confirmed => "(confirmed IS TRUE)",
        # given    => recherche par date ?
    );

    # SQL options
    my %opt = (
        offset   => '',
        limit    => '',
    );
    
    # clean up the arguments and options
    exists $args{$_} and $opt{$_} = delete $args{$_} for keys %opt;
    $opt{$_} =~ s/\D+//g for qw( offset limit );
    for( keys %args ) {
        # ignore search attributes we do not know
        delete $args{$_} unless exists $req{$_};
        # remove empty or false search attributes
        delete $args{$_} unless $args{$_};
    }

    # special cases
    $args{name} = [ ( $args{name} ) x 3 ] if exists $args{name};

    # build the request string
    my $SQL = "SELECT DISTINCT * FROM talks WHERE ";
    $SQL .= join " AND ", "TRUE", @req{keys %args};
    $SQL .= join " ", "", map { $opt{$_} ne '' ? ( uc, $opt{$_} ) : () }
                          keys %opt;

    # run the request
    my $sth = $Request{dbh}->prepare_cached( $SQL );
    $sth->execute( map { (ref) ? @$_ : $_ } values %args );

    my ($talks, $talk) = [ ];
    push @$talks, bless $talk, $class while $talk = $sth->fetchrow_hashref();

    $sth->finish();

    return $talks;
}

1;

