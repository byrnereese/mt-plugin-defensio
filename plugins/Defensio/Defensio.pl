# Copyright (C) 2008, Six Apart, Ltd.
# GNU General Public License, version 2.
#
# $Id: $

package MT::Plugin::Defensio;

use strict;

use Carp qw( croak );
use MT::Util qw( format_ts );

use base qw( MT::Plugin );
our $VERSION = '1.0';

my $plugin;
{
    my $settings = [
        ['api_key', { Scope => 'system'} ],
    ];
    my $about = {
        name                   => 'Defensio',
        id                     => 'defensio',
        key                    => __PACKAGE__,
        author_name            => 'Six Apart Ltd.',
        author_link            => 'http://www.sixapart.com/',
        version                => $VERSION,
	schema_version         => 2,
#        blog_config_template   => 'config.tmpl',
        system_config_template => 'system.tmpl',
        settings               => MT::PluginSettings->new($settings),
        l10n_class             => 'Defensio::L10N',
        registry => {
	    object_types => {
		'comment' => {
		    defensio_spaminess => 'float',
		    defensio_sig => 'string(255)',
		    defensio_is_spam => 'smallint',
		},
	    },
            callbacks => {
                handle_spam => \&handle_junk,
                handle_ham => \&handle_not_junk,
                'MT::Entry::post_save' => \&post_save_obj,
                'MT::Comment::pre_save' => \&pre_save_feedback_obj,
                'MT::TBPing::pre_save' => \&pre_save_feedback_obj,
            },
            junk_filters => {
                'Defensio' => {
                    label => 'Defensio AntiSpam',
                    code => \&defensio_score,
                },
            },
        },
    };
    $plugin = __PACKAGE__->new($about);
}
MT->add_plugin($plugin);
if (MT->version_number < 4) {
    MT->add_callback('HandleJunk',    5, $plugin, \&handle_junk);
    MT->add_callback('HandleNotJunk', 5, $plugin, \&handle_not_junk);
    MT->register_junk_filter({
        name => 'DefensioAntiSpam',
        code => \&defensio_score
    });
}

#--- plugin handlers

sub instance {
    return $plugin;
}

sub description {
    my $plugin = shift;
    my $app = MT->instance;
    my $blog;
    if ($app->isa('MT::App::CMS')) {
        $blog = $app->blog;
    }
    my $desc = '<p>' . $plugin->translate('Defensio is a spam filtering web service that you can use to protect your blog or web application from comment spam. ') . '</p>';
    return $desc;
}

sub save_config {
    my $plugin = shift;
    my ($args, $scope) = @_;

    my $app = MT->instance;

    $scope ||= 'system';
    if ( $scope eq 'system' ) {
        my $existing_api_key = $plugin->api_key || '';
        my $new_api_key = $args->{api_key} || '';
        if ( ($new_api_key ne '') && ( $new_api_key ne $existing_api_key ) ) {
            # user assigned a new API key
	    require Net::Defensio;
            my $url = $app->base . $app->mt_uri;
	    my $cli = Net::Defensio->new( api_key => $new_api_key ); 
            my $res = $cli->validate_key( owner_url => $url ); 
            if ( !$res || !$res->success ) {
                return $plugin->error($plugin->translate("Failed to verify your Defensio API key: [_1]", "unknown error"));
            } elsif ( $res->status eq 'fail' ) {
                return $plugin->error($plugin->translate("The Defensio API key provided is invalid: ") . $res->message);
            }
       }
    }
    my $result = $plugin->SUPER::save_config(@_);
    return $result;
}

sub pre_save_feedback_obj {
    my ($cb, $obj, $orig) = @_;
    1;
}

# This callback handler reports new entries to Defensio
sub post_save_obj {
    my ($cb, $obj, $orig) = @_;
    my $key    = get_apikey() or return;
    my $cli    = Net::Defensio->new( api_key => $key ); 
    my $url = $app->base . $app->mt_uri;
    my $res = $cli->announce_article( 
	owner_url => $url,
	article_author => $obj->author->name,
	article_author_email => $obj->author->email,
	article_title => $obj->title,
	article_content => $obj->text,
	permalink => $obj->permalink,
	); 
    if ( !$res || !$res->success ) {
	MT->log("Communications failure with Defensio");
    } elsif ( $res->status eq 'fail' ) {
	MT->log("Defensio error: " . $res->message);
    }
    1;
}

# Report the comment as SPAM
# Report the comment as a false negative
sub handle_junk {
    my ($cb, $app, $thing) = @_;
    my $key    = get_apikey() or return;
    require Net::Defensio;
    if (!$thing->defensio_sig) { # comment has NOT been rated by Defensio before
	my ($score,$grade) = defensio_score($thing);
    }
    # only do the following if Defensio thinks this is SPAM
    if (!$thing->defensio_is_spam) {
	my $cli    = Net::Defensio->new( api_key => $key ); 
	my $url = $app->base . $app->mt_uri;
	my $res = $cli->report_false_negatives( 
	    owner_url => $url,
	    signatures => $thing->defensio_sig,
	    ); 
	if ( !$res || !$res->success ) {
	    MT->log("Communications failure with Defensio");
	} elsif ( $res->status eq 'fail' ) {
	    MT->log("Defensio error: " . $res->message);
	}
    }
}

# Report the comment as HAM
# Report the comment as a false positive
sub handle_not_junk {
    my ($cb, $app, $thing) = @_;

    my $key    = get_apikey()  or return;
    require Net::Defensio;
    if (!$thing->defensio_sig) { # comment has NOT been rated by Defensio before
	my ($score,$grade) = defensio_score($thing);
    }
    # only do the following if Defensio thinks this is SPAM
    if ($thing->defensio_is_spam) {
	my $cli    = Net::Defensio->new( api_key => $key ); 
	my $url = $app->base . $app->mt_uri;
	my $res = $cli->report_false_positives( 
	    owner_url => $url,
	    signatures => $thing->defensio_sig,
	    ); 
	if ( !$res || !$res->success ) {
	    MT->log("Communications failure with Defensio");
	} elsif ( $res->status eq 'fail' ) {
	    MT->log("Defensio error: " . $res->message);
	}
    }
}

sub defensio_score {
    my $thing = shift;
    require Net::Defensio;
    my $key    = get_apikey() or return MT::JunkFilter::ABSTAIN();

    my $cli    = Net::Defensio->new( api_key => $key ); 
    my $params = _build_audit_params($thing);
    my $res = $cli->audit_comment( %$params );
    if ( !$res || !$res->success ) {
        MT->log("Communications failure with Defensio");
    } elsif ( $res->status eq 'fail' ) {
	MT->log("Defensio error: " . $res->message);
    }

    return MT::JunkFilter::ABSTAIN()
        unless $res && $res->success;

    $thing->defensio_is_spam($res->status ? 0 : 1);
    $thing->defensio_sig($res->signature);
    $thing->defensio_spaminess($res->spaminess);

    my ($score, $grade) = $res->status ? (1, 'ham') : (-1 * $res->spaminess, 'spam');
    ($score, ["Defensio says $grade"]);
}

#--- utility

sub _build_audit_params {
    my ($thing) = @_;
    require MT::Author;
    my $commenter = MT::Author->load($thing->commenter_id);
    my $entry     = $thing->entry;
    my $params    = {
	'owner-url'            => $entry->blog->site_url,
	'user-ip'              => $thing->ip,
	'article-date'         => format_ts('%Y/%m/%d',$entry->authored_on),
	'comment-author'       => $commenter->name,
	'comment-type'         => 'comment',
	# optional
	'comment-content'      => $thing->text,
	'comment-author-email' => $thing->email,
	'comment-author-url'   => $thing->url,
	'permalink'            => $entry->permalink,
#	'referrer'             => '',
	'trusted-user'         => $commenter->is_trusted(),
#	'user-logged-in'       => ($commenter->author =~ /^https?:/i ? 1 : 0),
#	'openid'               => ($commenter->author =~ /^https?:/i ? $commenter->author : undef),
    };
    return $params;
}

sub get_apikey {
    my $thing = shift;
    my $r     = MT->request;
    unless ($r->stash('MT::Plugin::Defensio::api_key')) {
        my $key = $plugin->api_key || return;
        $r->stash('MT::Plugin::Defensio::api_key', $key);
    }
    $r->stash('MT::Plugin::Defensio::api_key');
}

sub cache {
    my $id    = shift;
    my $cache = MT->request->stash('MT::Plugin::Defensio::permalinks');
    unless ($cache) {
        $cache = {};
        MT->request->stash('MT::Plugin::Defensio::permalinks', $cache);
    }
    unless ($cache->{$id}) {
        if ($id =~ /^B/) {
            my $b = MT::Blog->load(substr($id, 1)) or return;
            $cache->{$id} = $b->site_url;
        } else {
            require MT::Entry;
            my $e = MT::Entry->load($id) or return;
            $cache->{$id} = $e->permalink;
        }
    }
    $cache->{$id};
}

sub api_key {
    my $plugin = shift;
    my $blog = shift;
    if (@_) {
        my $key = shift;
        $plugin->set_config_value('api_key', $key);
    } else {
        return $plugin->get_config_value('api_key');
    }
}

#sub blocked {
#    my $plugin = shift;
#    my $blog = shift;
#    my $blog_id = (ref($blog) && $blog->isa('MT::Blog')) ? $blog->id : $blog;
#    my $blocked = $plugin->get_config_value('blocked', $blog_id ? 'blog:' . $blog_id : 'system');
#    return $blocked || 0 unless @_;
#    my ($count) = @_;
#    $plugin->set_config_value('blocked', $count, $blog_id ? 'blog:' . $blog_id : 'system');
#    return $count;
#}

1;
