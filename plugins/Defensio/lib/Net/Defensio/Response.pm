package Net::Defensio::Response;

our $VERSION = '0.01';
use base qw( Class::Accessor::Fast );

__PACKAGE__->mk_accessors(qw(
    action
    status message api_version
    spam spaminess signature
    ham false_positives false_negatives accuracy
    learning learning_message
));

sub success {
    my $r = shift;
    return ($r->status || '') eq 'success';
}

sub is_spam {
    my $r = shift;
    return undef unless defined $r->spam;
    $r->spam eq 'true' ? 1 : 0;
}

sub is_ham {
    my $r = shift;
    return undef unless defined $r->spam;
    $r->spam eq 'false' ? 1 : 0;
}

1;
__END__

=head1 NAME

Net::Defensio::Response - Object for holding response to a Net::Defensio request.

=head1 SYNOPSIS

    my $r = $defensio->audit_comment( ..... )
        or die $defensio->errstr;
    if ($r->success) {
        print "Spaminess: " . $r->spaminess . "\n";
    } else {
        print "Failure: " . $r->message . "\n";
    }

=head1 METHODS

=head2 Net::Defensio::Response->new( \%data )

Constructs a new C<Net::Defensio::Response> object, initializing it with
the parameter data given.

=head2 $response->success

Returns a true value when the 'status' member is set to 'true'. Returns
false otherwise.

=head2 $response->is_spam

Returns a true value when the 'spam' member is set to 'true'. Only useful
for responses to 'audit-comment' requests.

=head2 $response->is_ham

Returns a true value when the 'spam' member is set to 'false'. Only useful
for responses to 'audit-comment' requests.

=head2 $response->action

Holds the name of the 'action' for the Defensio API request. Set for all
response objects.

=head2 $response->status

Holds the status member of a Defensio API response. Will be set to either
'success' or 'fail'. Set for all response objects.

=head2 $response->message

Holds the message member of a Defensio API response. Set for all response
objects, but may be an empty string.

=head2 $response->api_version

Holds the api-version member of a Defensio API response. Set for all response
objects.

=head2 $response->spam

For 'audit-comment' requests, this contains a boolean value, represented
as 'true' or 'false'.

For 'get-stats' requests, this contains an integer of the number of messages
Defensio has rated as spam.

=head2 $response->spaminess

For 'audit-comment' requests. Holds the floating-point value of the
"spaminess" of the comment.

=head2 $response->signature

For 'audit-comment' requests. Holds the signature member of the Defensio
response.

=head2 $response->ham

For 'get-stats' requests, this contains an integer of the number of messages
Defensio has rated as ham (legitimate comments).

=head2 $response->false_positives

For 'get-stats' requests, this contains an integer of the number of messages
that have been submitted to Defensio for retraining as spam.

=head2 $response->false_negatives

For 'get-stats' requests, this contains an integer of the number of messages
that have been submitted to Defensio for retraining as non-spam.

=head2 $response->accuracy

For 'get-stats' requests, this contains a floating-point number representing
the accuracy of the Defensio filters (from 0 to 1; 0 being 100% inaccurate,
1 being 100% accurate).

=head2 $response->learning

For 'get-stats' requests, this contains a boolean value indicating whether
the Defensio filter is still in 'learning mode' for the account being
used (either set to 'true' or 'false').

=head2 $response->learning_message

For 'get-stats' requests, this contains a message explaining why the
Defensio filter is still in 'learning mode'. Only relevant when 'learning'
is returned as 'true'.

=head1 COPYRIGHT & LICENSE

Copyright 2007 Brad Choate, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut