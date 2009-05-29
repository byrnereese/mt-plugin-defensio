package Net::Defensio;

# TODO: XML format support, YAML::Syck support

use strict;
use Net::Defensio::Response;

our $VERSION = '0.02';
our $ERROR;
our $API_VERSION = '1.1';

my $UA = "Perl-Net-Defensio/$VERSION";

our $REQUEST_PARAMS = {
    'validate-key' => { required => [ qw( owner-url ) ] },
    'announce-article' => { required => [ qw( owner-url article-author
        article-author-email article-title article-content permalink ) ] },
    'audit-comment' => { required => [ qw( owner-url user-ip
        article-date comment-author comment-author-email
        comment-type ) ],
        optional => [ qw( comment-content
        comment-author-url permalink referrer user-logged-in
        trusted-user test-force ) ] },
    'report-false-negatives' => { required => [ qw( owner-url
        signatures ) ] },
    'report-false-positives' => { required => [ qw( owner-url
        signatures ) ] },
    'get-stats' => { required => [ qw( owner-url ) ] },
};
our $RESPONSE_PARAMS = {
    'validate-key' => [ qw( status message api-version ) ],
    'announce-article' => [ qw( status message api-version ) ],
    'audit-comment' => [ qw( status message api-version signature
        spam spaminess ) ],
    'report-false-negatives' => [ qw( status message api-version ) ],
    'report-false-positives' => [ qw( status message api-version ) ],
    'get-stats' => [ qw( status message api-version accuracy spam ham
        false-positives false-negatives learning learning-message ) ],
};

sub new {
    my $pkg = shift;
    $pkg = ref $pkg if ref $pkg;

    my (%param) = @_;

    return $pkg->error("Required parameter missing: 'api_key'")
        unless $param{api_key};

    my $obj = { api_key => $param{api_key} };
    $obj->{user_agent} = delete $param{user_agent};
    $obj->{agent} = delete $param{agent} || $UA;
    $obj->{api_version} = delete $param{api_version} || $API_VERSION;
    $obj->{host} = delete $param{host} || 'api.defensio.com';
    $obj->{format} = delete $param{format} || 'yaml';
    $obj->{service_type} = delete $param{service_type} || 'app';
    $obj->{protocol} = delete $param{protocol} || 'http';
    $obj->{port} = delete $param{port} || 80;

    return bless $obj, $pkg;
}

sub user_agent {
    my $obj = shift;
    $obj->{user_agent} = shift if @_;
    return $obj->{user_agent} if $obj->{user_agent};
    require LWP::UserAgent;
    return $obj->{user_agent} = LWP::UserAgent->new;
}

sub service_url {
    my $obj = shift;
    my (%param) = @_;

    my $action = $param{action}
        or return $obj->error("'action' parameter required");

    my $protocol = $param{protocol} || $obj->{protocol};
    my $host = $param{host} || $obj->{host};
    my $port = $param{port} || $obj->{port};
    if (($port ne '') && ($port != 80)) {
        $port = ':' . $port;
    } else {
        $port = '';
    }
    my $service_type = $param{service_type} || $obj->{service_type};
    my $api_version = $param{api_version} || $obj->{api_version};
    my $api_key = $param{api_key} || $obj->{api_key};
    my $format = $param{format} || $obj->{format};

    my $url = join "/", "$protocol:/", "$host$port",
        $service_type, $api_version, $action, "$api_key.$format";

    return $url;
}

sub safe_submit {
    my $obj = shift;
    my ($action, $param) = @_;

    return $obj->error("Invalid request for unknown '$action'")
        unless exists $REQUEST_PARAMS->{$action};

    my $req_params = $REQUEST_PARAMS->{$action}{required} || [];
    my $opt_params = $REQUEST_PARAMS->{$action}{optional} || [];
    my %req_param;
    my @params;

    foreach my $p (@$req_params) {
        (my $under_p = $p) =~ s/-/_/g;
        my $val;
        foreach ($p, $under_p, lc($under_p)) {
            $val = $param->{$_}, last if exists $param->{$_};
        }
        return $obj->error("Required parameter missing: '$p'")
            unless defined $val;
        push @params, $p, $val if defined $val;
    }
    foreach my $p (@$opt_params) {
        (my $under_p = $p) =~ s/-/_/g;
        my $val;
        foreach ($p, $under_p, lc($under_p)) {
            $val = $param->{$_}, last if exists $param->{$_};
        }
        push @params, $p, $val if defined $val;
    }

    my $service_url = $param->{'service-url'} || $param->{service_url} ||
        $obj->service_url( action => $action, %$param );

    my $response = $obj->user_agent->post( $service_url, \@params );

    if ($response && !$response->is_success()) {
        return $obj->error("Error with $action request: "
            . $response->status_line);
    }
    elsif (!$response) {
        return $obj->error("Error with $action request");
    }

    $obj->process_http_response($action, $response);
}

sub process_http_response {
    my $obj = shift;
    my ($action, $http_resp) = @_;

    my $content = $http_resp->content();
    my $result = {};
    if ($content =~ m/^\s*<\?xml/) {
        # process as xml!
    }
    else {
        # process as yaml!
        require YAML::Tiny;
        my $y = YAML::Tiny->read_string($content);
        my $doc = $y->[0];
        my $resp_params = $RESPONSE_PARAMS->{$action};
        foreach my $p (@$resp_params) {
            my $val = $doc->{'defensio-result'}{$p};
            $p =~ s/-/_/g;
            if (defined $val) {
                $result->{$p} = $val;
            }
        }
    }
    $result->{action} = $action;
    return Net::Defensio::Response->new($result);
}

# API methods

sub validate_key {
    my $obj = shift;
    my (%param) = @_;
    $obj->safe_submit('validate-key', \%param);
}

sub announce_article {
    my $obj = shift;
    my (%param) = @_;
    $obj->safe_submit('announce-article', \%param);
}

sub audit_comment {
    my $obj = shift;
    my (%param) = @_;
    $obj->safe_submit('audit-comment', \%param);
}

sub report_false_negatives {
    my $obj = shift;
    my (%param) = @_;
    $obj->safe_submit('report-false-negatives', \%param);
}

sub report_false_positives {
    my $obj = shift;
    my (%param) = @_;
    $obj->safe_submit('report-false-positives', \%param);
}

sub get_stats {
    my $obj = shift;
    my (%param) = @_;
    $obj->safe_submit('get-stats', \%param);
}

# Error API

sub errstr {
    my $pkg = shift;
    return ref($pkg) ? $pkg->{error} : $ERROR;
}

sub error {
    my $pkg = shift;
    (ref($pkg) ? $pkg->{error} : $ERROR) = shift;
    return undef;
}

1;
__END__

=head1 NAME

Net::Defensio - Perl interface for Defensio.com antispam services.

=head1 VERSION

Version 0.01

=head1 DESCRIPTION

This module provides a simple interface for using the Defensio.com
antispam service.

=head1 SYNOPSIS

    use Net::Defensio;
    my $defensio = Net::Defensio->new( api_key => '...' );
    my $response = $defensio->audit_comment(
        owner_url => 'http://example.com/',
        ...
    );
    if ($response && $response->success) {
        if ($response->spam) {
            print "Comment is spam: " . $response->spaminess . "\n";
        }
        else {
            print "Comment is ham!\n";
        }
    } else {
        print "Error with request: "
            . $response ? $response->message : $defensio->errstr;
    }

=head1 METHODS

=head2 Net::Defensio->new( %params )

Constructs a new C<Net::Defension> instance. Acceptable parameters:

=over 4

=item * api_key

The API key provided by defensio.com. This is a required parameter.

=item * host

The defensio.com API hostname to use (default is 'api.defensio.com').

=item * protocol

The protocol name to use for the request (default is 'http').

=item * agent

The user agent string to use for API requests (default is
'Perl-Net-Defensio/VERSION').

=item * user_agent

A L<LWP::UserAgent> object to use for API requests. If not supplied,
one will be created.

=item * api_version

The API version number to use for requests (this currently defaults to
'1.1').

=item * format

The format to request for the response from Defensio (defaults to 'yaml').

=item * service_type

Denotes the type of service being requested (currently supported are:
"app" (i.e. use of Defensio within an application) and "blog" (i.e.
use of Defensio to support a blogging platform). The default value is
'app', but you should override this if your application is a blogging
application.

=back

=head2 $defensio->validate_key( %params )

Issues a 'validate-key' API request. The parameters for this request are
(all of these parameters are required for this request):

=over 4

=item * owner_url

The URL of the site owner using the service.

=back

The response object returned will have these members assigned:

=over 4

=item * status

Indicates whether or not the action could be processed ('success' or
'fail').

=item * message

A message provided by the action if applicable.

=item * api_version

The version of the API used to process the request.

=back

Returns a L<Net::Defensio::Response> object. If successful, the response
object's 'success' method will be true. Otherwise, you can check for
the error message with the response object's 'message' method.

=head2 $defensio->announce_article( %params )

Issues an 'announce-article' API request. The parameters for this request
are (all of these parameters are required for this request):

=over 4

=item * owner_url

The URL of the site owner using the service.

=item * article_author

The name of the author of the article.

=item * article_author_email

The email address of the person posting the article.

=item * article_title

The title of the article.

=item * article_content

The content of the blog posting itself.

=item * permalink

The permalink of the article just posted.

=back

The response object returned will have these members assigned:

=over 4

=item * status

Indicates whether or not the action could be processed ('success' or
'fail').

=item * message

A message provided by the action if applicable.

=item * api_version

The version of the API used to process the request.

=back

Notes: This request is important in the accuracy of the Defensio filtering
engine. Defensio expects this request to be issued upon initial publication
of an article. It should not be issued for private or otherwise unpublished
articles. It should also not be re-issued with edits to the article.

=head2 $defensio->audit_comment( %params )

Issues an 'audit-comment' API request. The parameters for this request
are:

=over 4

=item * owner-url

The URL of the site owner using the service.

=item * user-ip

The IP address of whomever is posting the comment.

=item * article-date

The date the original blog article was posted (should be in this format:
yyyy/mm/dd).

=item * comment-author

The name of the author of the comment.

=item * comment-type

The type of the comment being posted to the blog (acceptable values are
'comment', 'trackback', 'pingback', 'other').

=item * comment-content

(optional) The actual content of the comment (strongly recommended to be
included where ever possible).

=item * comment-author-email

(optional) The email address of the person posting the comment.

=item * comment-author-url

(optional) The URL of the person posting the comment.

=item * permalink

(optional) The permalink of the blog post to which the comment is
being posted.

=item * referrer

(optional) The URL of the site that brought commenter to this page.

=item * user-logged-in

(optional) Whether or not the user posting the comment is logged into
the blogging platform (either 'true' or 'false').

=item * trusted-user

(optional) Whether or not the user is an administrator, moderator or
editor of this blog; the client should pass true only if blogging
platform can guarantee that the user has been authenticated and has a
role of responsibility on this blog (either 'true' or 'false').

=item * test-force

(optional and FOR TESTING PURPOSES ONLY) Use this parameter to force
the outcome of audit-comment. Optionally affix (with a comma) a desired
spaminess return value (in the range 0 to 1).

=back

The response object returned will have these members assigned:

=over 4

=item * status

Indicates whether or not the action could be processed ('success' or
'fail').

=item * message

A message provided by the action if applicable.

=item * api_version

The version of the API used to process the request.

=item * signature

A message signature that uniquely identifies the comment in the Defensio
system. This signature should be stored by the client for retraining
purposes.

=item * spam

A boolean value indicating whether Defensio believes the comment to be
spam ('true' or 'false').

=item * spaminess

A value indicating the relative likelihood of the comment being spam. This
value should be stored by the client for use in building convenient spam
sorting user-interfaces (a float between 0 and 1, e.g. 0.9893)

=back

=head2 $defensio->report_false_negatives( %params )

Issues an 'report-false-negatives' API request. The parameters for this
request are:

=over 4

=item * owner-url

The URL of the site owner using the service.

=item * signatures

List of signatures (may contain a single entry) of
the comments to be submitted for retraining. Note that a signature
for each comment was originally provided by Defensio's audit-comment
action. For multiple signatures, use a comma as a delimiter.

=back

The response object returned will have these members assigned:

=over 4

=item * status

Indicates whether or not the action could be processed ('success' or
'fail').

=item * message

A message provided by the action if applicable.

=item * api_version

The version of the API used to process the request.

=back

=head2 $defensio->report_false_positives( %params )

Issues an 'report-false-positives' API request. The parameters for this
request are:

=over 4

=item * owner-url

The URL of the site owner using the service.

=item * signatures

List of signatures (may contain a single entry) of the comments to be
submitted for retraining. Note that a signature for each comment was
originally provided by Defensio's audit-comment action. For multiple
signatures, use a comma as a delimiter.

=back

The response object returned will have these members assigned:

=over 4

=item * status

Indicates whether or not the action could be processed ('success' or
'fail').

=item * message

A message provided by the action if applicable.

=item * api_version

The version of the API used to process the request.

=back

=head2 $defensio->get_stats( %params )

Issues an 'get-stats' API request. The parameters for this
request are:

=over 4

=item * owner-url: The URL of the site owner using the service.

=back

The response object returned will have these members assigned:

=over 4

=item * status

Indicates whether or not the action could be processed ('success' or 'fail').

=item * message

A message provided by the action if applicable.

=item * api_version

The version of the API used to process the request.

=item * accuracy

Describes the percentage of comments correctly identified as spam/ham by
Defensio on this blog (returns a float between 0 and 1, e.g. 0.9983).

=item * spam

The number of spam comments caught by the filter.

=item * ham

The number of ham (legitimate) comments accepted by the filter.

=item * false_positives

The number of times a legitimate message was retrained from the spambox
(i.e. "de-spammed" by the user).

=item * false_negatives

The number of times a spam message was retrained from comments box (i.e.
"de-legitimized" by the user).

=item * learning

A boolean value indicating whether Defensio is still in its initial
learning phase ('true' or 'false').

=item * learning_message

More details on the reason(s) why Defensio is still in its initial
learning phase.

=back

=head1 COPYRIGHT & LICENSE

Copyright 2007 Brad Choate, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

