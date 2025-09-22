#!/usr/bin/env perl

# RSS Feed Generator for Hashcat Monitoring
#
# Purpose: Convert Hashcat monitoring changes into RSS feed format
# Methodology:
#   1. Parse changes from monitor script output
#   2. Load existing RSS feed or create new one
#   3. Add new changes as RSS items with proper metadata
#   4. Maintain feed with maximum item limit for performance
#   5. Generate valid RSS 2.0 XML with security-relevant categorization
#
# Design choices:
#   - Uses XML::RSS for proper RSS 2.0 format compliance
#   - Limits feed to 50 items to prevent excessive growth
#   - Includes security-relevant metadata and categories
#   - Handles both incremental updates and feed initialization
#   - Provides detailed item descriptions with change context

use strict;                    # Enforce strict variable declarations
use warnings;                  # Enable comprehensive warning system
use XML::RSS;                  # RSS feed generation and manipulation
use DateTime;                  # Date/time handling for RSS timestamps
use File::Slurp;              # Simplified file operations
use Digest::MD5 qw(md5_hex);   # For generating unique item IDs

# Configuration constants
my $MAX_ITEMS = 50;           # Maximum number of items to keep in feed
my $FEED_TITLE = 'Hashcat Repository Monitor';
my $FEED_DESCRIPTION = 'Automated monitoring of Hashcat package changes across repositories';
my $FEED_LINK = 'https://github.com/' . ($ENV{GITHUB_REPOSITORY} || 'user/repo');

# Get command line arguments
my ($changes_file, $rss_file) = @ARGV;

# Validate command line arguments
if (!$changes_file || !$rss_file) {
    die "Usage: $0 <changes_file> <rss_file>\n";
}

# Main execution flow
sub main {
    print "=== RSS Feed Generator ===\n";
    print "Processing changes from: $changes_file\n";
    print "Output RSS file: $rss_file\n\n";

    # Parse changes from monitor output
    my $changes = parse_changes_file($changes_file);

    # Load existing RSS feed or create new one
    my $rss = load_or_create_rss($rss_file);

    # Add changes to RSS feed if any were found
    if (@$changes > 0) {
        print "Adding " . scalar(@$changes) . " change(s) to RSS feed...\n";
        add_changes_to_rss($rss, $changes);
    } else {
        print "No changes to add to RSS feed.\n";
        # Update the feed timestamp even if no changes
        update_feed_metadata($rss);
        add_no_changes_item($rss);
    }

    # Limit feed size and save
    limit_feed_items($rss);
    save_rss_feed($rss, $rss_file);

    print "RSS feed updated successfully.\n";
}

# Parse the changes file and extract meaningful change information
# Input: path to changes file
# Returns: arrayref of change hashrefs
sub parse_changes_file {
    my ($file_path) = @_;
    my @changes = ();

    print "Parsing changes file...\n";

    # Read the entire changes file
    my $content;
    eval {
        $content = read_file($file_path);
    };
    if ($@) {
        warn "Could not read changes file '$file_path': $@\n";
        return \@changes;
    }

    # Split content into lines for processing
    my @lines = split /\n/, $content;
    my $current_change = undef;

    # Process each line to identify changes
    foreach my $line (@lines) {
        # Remove leading/trailing whitespace
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '';  # Skip empty lines

        # Detect new package additions
        if ($line =~ /^NEW PACKAGE:\s+(.+)$/) {
            # Finish previous change if exists
            push @changes, $current_change if $current_change;

            # Start new change entry
            $current_change = {
                type => 'new_package',
                package => $1,
                description => "New package detected: $1",
                details => []
            };
        }
        # Detect package changes
        elsif ($line =~ /^CHANGES in\s+(.+):$/) {
            # Finish previous change if exists
            push @changes, $current_change if $current_change;

            # Start new change entry
            $current_change = {
                type => 'package_change',
                package => $1,
                description => "Changes detected in package: $1",
                details => []
            };
        }
        # Detect removed packages
        elsif ($line =~ /^REMOVED PACKAGE:\s+(.+)$/) {
            # Finish previous change if exists
            push @changes, $current_change if $current_change;

            # Start new change entry
            $current_change = {
                type => 'removed_package',
                package => $1,
                description => "Package removed: $1",
                details => []
            };
        }
        # Capture field changes (indented lines with field: old -> new format)
        elsif ($line =~ /^\s+(.+):\s+'(.+)'\s+->\s+'(.+)'$/ && $current_change) {
            my ($field, $old_val, $new_val) = ($1, $2, $3);
            push @{$current_change->{details}}, {
                field => $field,
                old_value => $old_val,
                new_value => $new_val
            };
        }
        # Capture package information (indented field: value format)
        elsif ($line =~ /^\s+(.+):\s+(.+)$/ && $current_change) {
            my ($field, $value) = ($1, $2);
            push @{$current_change->{details}}, {
                field => $field,
                value => $value
            };
        }
    }

    # Don't forget the last change
    push @changes, $current_change if $current_change;

    print "Found " . scalar(@changes) . " change(s) to process.\n";
    return \@changes;
}

# Load existing RSS feed or create a new one
# Input: path to RSS file
# Returns: XML::RSS object
sub load_or_create_rss {
    my ($file_path) = @_;
    my $rss = XML::RSS->new(version => '2.0');

    # Try to load existing RSS feed
    if (-f $file_path) {
        print "Loading existing RSS feed...\n";
        eval {
            $rss->parsefile($file_path);
            print "Loaded existing feed with " . scalar(@{$rss->{items}}) . " items.\n";
        };
        if ($@) {
            warn "Could not parse existing RSS file, creating new feed: $@\n";
            $rss = create_new_rss_feed();
        }
    } else {
        print "Creating new RSS feed...\n";
        $rss = create_new_rss_feed();
    }

    return $rss;
}

# Create a new RSS feed with proper metadata
# Returns: XML::RSS object with channel information set
sub create_new_rss_feed {
    my $rss = XML::RSS->new(version => '2.0');

    # Set channel information
    $rss->channel(
        title => $FEED_TITLE,
        link => $FEED_LINK,
        description => $FEED_DESCRIPTION,
        language => 'en-us',                    # RSS language code
        copyright => 'Public Domain',           # Copyright information
        managingEditor => 'security-monitor@github.com',
        webMaster => 'security-monitor@github.com',
        category => 'Security Tools',           # RSS category
        generator => 'Hashcat Monitor Script',  # Generator identification
        ttl => 360,                            # Time to live (6 hours in minutes)
        lastBuildDate => DateTime->now->strftime('%a, %d %b %Y %H:%M:%S %Z'),
        pubDate => DateTime->now->strftime('%a, %d %b %Y %H:%M:%S %Z')
    );

    return $rss;
}

# Add parsed changes to the RSS feed as new items
# Input: XML::RSS object, arrayref of changes
sub add_changes_to_rss {
    my ($rss, $changes) = @_;

    my $now = DateTime->now();

    # Process each change and add as RSS item
    foreach my $change (@$changes) {
        # Generate unique ID for this change
        my $change_id = generate_change_id($change, $now);

        # Check if this change already exists in the feed
        my $exists = 0;
        foreach my $item (@{$rss->{items}}) {
            if ($item->{guid} && $item->{guid} eq $change_id) {
                $exists = 1;
                last;
            }
        }

        # Skip if this change already exists
        next if $exists;

        # Build detailed description
        my $description = build_change_description($change);

        # Determine category based on change type
        my $category = get_change_category($change);

        # Add item to RSS feed
        $rss->add_item(
            title => $change->{description},
            link => $FEED_LINK . '/actions',     # Link to GitHub Actions
            description => $description,
            pubDate => $now->strftime('%a, %d %b %Y %H:%M:%S %Z'),
            guid => $change_id,                  # Unique identifier
            category => $category                # Security-relevant category
        );

        print "Added RSS item: $change->{description}\n";
    }
}

# Generate a unique ID for a change based on its content and timestamp
# Input: change hashref, DateTime object
# Returns: unique string identifier
sub generate_change_id {
    my ($change, $datetime) = @_;

    # Create a unique string from change content
    my $content = $change->{type} . '|' . $change->{package} . '|' .
                  join('|', map { $_->{field} . ':' . ($_->{new_value} || $_->{value} || '') }
                       @{$change->{details}});

    # Add timestamp to ensure uniqueness
    $content .= '|' . $datetime->epoch;

    # Return MD5 hash for consistent ID length
    return md5_hex($content);
}

# Build detailed HTML description for RSS item
# Input: change hashref
# Returns: HTML formatted string
sub build_change_description {
    my ($change) = @_;

    my $html = "<div><strong>Package:</strong> $change->{package}</div>";
    $html .= "<div><strong>Change Type:</strong> " . format_change_type($change->{type}) . "</div>";

    # Add details if available
    if (@{$change->{details}} > 0) {
        $html .= "<div><strong>Details:</strong></div><ul>";

        foreach my $detail (@{$change->{details}}) {
            if (exists $detail->{old_value} && exists $detail->{new_value}) {
                # Field change format
                $html .= "<li><strong>$detail->{field}:</strong> " .
                        "<code>$detail->{old_value}</code> → " .
                        "<code>$detail->{new_value}</code></li>";
            } elsif (exists $detail->{value}) {
                # Field information format
                $html .= "<li><strong>$detail->{field}:</strong> <code>$detail->{value}</code></li>";
            }
        }

        $html .= "</ul>";
    }

    # Add security context
    $html .= "<div><em>This change affects the Hashcat password recovery tool. " .
             "Security professionals should review for potential impact on security assessments.</em></div>";

    return $html;
}

# Convert change type to human-readable format
# Input: change type string
# Returns: formatted string
sub format_change_type {
    my ($type) = @_;

    my %type_names = (
        'new_package' => 'New Package',
        'package_change' => 'Package Update',
        'removed_package' => 'Package Removal'
    );

    return $type_names{$type} || $type;
}

# Determine RSS category based on change type
# Input: change hashref
# Returns: category string
sub get_change_category {
    my ($change) = @_;

    # Check for version changes which are most important
    foreach my $detail (@{$change->{details}}) {
        if ($detail->{field} && $detail->{field} =~ /version/) {
            return 'Security Tools/Version Update';
        }
    }

    # Default categories by change type
    my %categories = (
        'new_package' => 'Security Tools/New Release',
        'package_change' => 'Security Tools/Update',
        'removed_package' => 'Security Tools/Deprecated'
    );

    return $categories{$change->{type}} || 'Security Tools';
}

# Update feed metadata without adding items
# Input: XML::RSS object
sub update_feed_metadata {
    my ($rss) = @_;

    # Update last build date
    $rss->channel(lastBuildDate => DateTime->now->strftime('%a, %d %b %Y %H:%M:%S %Z'));
}

sub add_no_changes_item {
    my ($rss) = @_;
    my $now = DateTime->now();

    # Check if a "no changes" item already exists to avoid duplicates
    foreach my $item (@{$rss->{items}}) {
        return if $item->{guid} && $item->{guid} eq 'no-changes-item-static-guid';
    }

    $rss->add_item(
        title => 'No new changes detected in Hashcat repository',
        link => $FEED_LINK . '/actions',
        description => 'The monitor ran at ' . $now->strftime('%a, %d %b %Y %H:%M:%S %Z') . ' and found no new changes.',
        pubDate => $now->strftime('%a, %d %b %Y %H:%M:%S %Z'),
        guid => 'no-changes-item-static-guid',
        category => 'Security Tools/Maintenance'
    );
    print "Added a maintenance item to the feed.\n";
}

# Limit RSS feed to maximum number of items
# Input: XML::RSS object
sub limit_feed_items {
    my ($rss) = @_;

    my $current_count = scalar(@{$rss->{items}});

    if ($current_count > $MAX_ITEMS) {
        print "Limiting feed to $MAX_ITEMS items (removing " . ($current_count - $MAX_ITEMS) . " oldest)\n";

        # Sort items by publication date (newest first)
        my @sorted_items = sort {
            # Convert date strings to comparable format - newer dates first
            ($b->{pubDate} || '') cmp ($a->{pubDate} || '')
        } @{$rss->{items}};

        # Keep only the newest MAX_ITEMS
        @{$rss->{items}} = splice(@sorted_items, 0, $MAX_ITEMS);
    }
}

# Save RSS feed to file
# Input: XML::RSS object, output file path
sub save_rss_feed {
    my ($rss, $file_path) = @_;

    print "Saving RSS feed to $file_path...\n";

    eval {
        # Generate RSS XML content
        my $rss_content = $rss->as_string;

        # Write to file
        write_file($file_path, $rss_content);
    };
    if ($@) {
        die "Could not save RSS feed: $@\n";
    }
}

# Execute main function with error handling
eval {
    main();
};
if ($@) {
    die "RSS generation failed: $@\n";
}
