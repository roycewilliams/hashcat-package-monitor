#!/usr/bin/env perl

# Hashcat API Monitor Script - FIXED VERSION
#
# Purpose: Monitor the Repology API for changes in specific Hashcat project fields
# Methodology:
#   1. Fetch current API data using HTTP::Tiny (lightweight HTTP client)
#   2. Parse JSON response (which returns an ARRAY of package objects)
#   3. Compare with previously stored state from a local file
#   4. Report any changes and update the stored state
#
# Design choices:
#   - Uses HTTP::Tiny instead of LWP for minimal dependencies
#   - JSON::PP is core Perl module for JSON parsing
#   - File-based storage for simplicity and persistence
#   - Process array of package objects (not nested hash structure)
#   - Human-readable output format for security monitoring use
#
# KEY FIX: API returns ARRAY of packages, not HASH with repo keys

use strict;                    # Enforce strict variable declarations and references
use warnings;                  # Enable all warning categories for better error detection
use HTTP::Tiny;               # Lightweight HTTP client module
use JSON::PP;                 # Pure Perl JSON parser/encoder (core module)
use Data::Dumper;             # For debugging data structures if needed
use Encode qw(decode encode);  # For proper UTF-8 handling (core module)

# Configuration constants
my $API_URL = 'https://repology.org/api/v1/project/hashcat';
my $STATE_FILE = 'hashcat_state.json';    # File to store previous API state
my @MONITORED_FIELDS = qw(version origversion status);  # Fields we want to track

# Main execution flow
sub main {
    print "=== Hashcat Repository Monitor ===\n";
    print "Monitoring fields: " . join(', ', @MONITORED_FIELDS) . "\n\n";

    # Fetch current data from API
    my $current_data = fetch_api_data();
    if (!$current_data) {
        die "Failed to fetch API data. Exiting.\n";
    }

    # Extract only the fields we care about from all packages
    my $current_filtered = extract_monitored_fields($current_data);

    # Load previous state if it exists
    my $previous_filtered = load_previous_state();

    # Compare states and report changes
    if ($previous_filtered) {
        compare_and_report_changes($previous_filtered, $current_filtered);
    } else {
        print "No previous state found. Initializing monitoring...\n";
        print_current_state($current_filtered);
    }

    # Save current state for next run
    save_current_state($current_filtered);

    print "\nMonitoring complete.\n";
}

# Fetch JSON data from the Repology API
# Returns: arrayref of parsed JSON data, or undef on failure
sub fetch_api_data {
    print "Fetching data from API...\n";

    # Create HTTP client with reasonable timeout
    my $http = HTTP::Tiny->new(timeout => 30);

    # Make GET request to API endpoint
    my $response = $http->get($API_URL);

    # Check if HTTP request was successful
    if (!$response->{success}) {
        warn "HTTP request failed: $response->{status} $response->{reason}\n";
        return undef;
    }

    # Parse JSON response body
    my $json = JSON::PP->new();
    my $data;
    eval {
        $data = $json->decode($response->{content});
    };
    if ($@) {
        warn "JSON parsing failed: $@\n";
        return undef;
    }

    # Verify we got an array as expected
    if (!defined $data || ref($data) ne 'ARRAY') {
        warn "Expected array from API, got: " . (ref($data) || 'scalar') . "\n";
        return undef;
    }

    print "Retrieved " . scalar(@$data) . " package entries from API\n";
    return $data;
}

# Extract only the monitored fields from all package entries
# Input: arrayref of package objects from API
# Returns: hashref with unique package IDs as keys, monitored fields as values
sub extract_monitored_fields {
    my ($packages) = @_;
    my $filtered = {};

    # Return empty hash if no data provided (defensive programming)
    return $filtered unless defined $packages && ref($packages) eq 'ARRAY';

    print "Processing " . scalar(@$packages) . " packages...\n";

    # Iterate through each package object in the array
    foreach my $package (@$packages) {
        # Skip if package data isn't a hash (unexpected format)
        next unless defined $package && ref($package) eq 'HASH';

        # Extract only the fields we're monitoring
        my $filtered_package = {};
        foreach my $field (@MONITORED_FIELDS) {
            # Store field value, or 'N/A' if field doesn't exist
            $filtered_package->{$field} = $package->{$field} // 'N/A';
        }

        # Create unique package identifier
        # Use repo + subrepo for uniqueness, as some distros have multiple subrepos
        my $repo = $package->{repo} // 'unknown_repo';
        my $subrepo = $package->{subrepo} // '';
        
        # Build package ID - include subrepo if it exists and differs from main repo
        my $package_id;
        if ($subrepo && $subrepo ne $repo) {
            $package_id = "$repo/$subrepo";
        } else {
            $package_id = $repo;
        }

        # Store the filtered package data
        $filtered->{$package_id} = $filtered_package;
    }

    print "Extracted data for " . scalar(keys %$filtered) . " unique repositories\n";
    return $filtered;
}

# Load the previous state from file if it exists
# Returns: hashref of previous data, or undef if no previous state
sub load_previous_state {
    # Check if state file exists before trying to read it
    return undef unless -f $STATE_FILE;

    print "Loading previous state...\n";

    # Read entire file content into scalar using core Perl operations
    my $json_content;
    eval {
        # Open file handle with proper error checking
        open(my $fh, '<:encoding(UTF-8)', $STATE_FILE) 
            or die "Cannot open $STATE_FILE for reading: $!";
        
        # Read entire file content (slurp mode)
        local $/; # Disable input record separator to read entire file
        $json_content = <$fh>;
        
        # Close file handle
        close($fh) or warn "Cannot close $STATE_FILE: $!";
    };
    if ($@) {
        warn "Could not read state file: $@\n";
        return undef;
    }

    # Parse JSON content
    my $json = JSON::PP->new();
    my $data;
    eval {
        $data = $json->decode($json_content);
    };
    if ($@) {
        warn "Could not parse state file JSON: $@\n";
        return undef;
    }

    return $data;
}

# Save current state to file for next comparison
# Input: hashref of current filtered data
sub save_current_state {
    my ($current_data) = @_;

    print "Saving current state...\n";

    # Convert data structure to pretty-printed JSON
    my $json = JSON::PP->new->pretty;
    my $json_content = $json->encode($current_data);

    # Write JSON to state file using core Perl operations
    eval {
        # Open file handle for writing with proper UTF-8 encoding
        open(my $fh, '>:encoding(UTF-8)', $STATE_FILE) 
            or die "Cannot open $STATE_FILE for writing: $!";
        
        # Write JSON content to file
        print $fh $json_content;
        
        # Close file handle and check for errors
        close($fh) or die "Cannot close $STATE_FILE: $!";
    };
    if ($@) {
        warn "Could not save state file: $@\n";
    }
}

# Compare previous and current states, report any changes found
# Input: hashref of previous data, hashref of current data
sub compare_and_report_changes {
    my ($previous, $current) = @_;

    print "Comparing with previous state...\n\n";

    my $changes_found = 0;  # Flag to track if any changes were detected

    # Check each repository/package in current data
    foreach my $package_id (sort keys %$current) {
        my $current_package = $current->{$package_id};
        my $previous_package = $previous->{$package_id};

        # Handle new repositories/packages
        if (!$previous_package) {
            print "NEW PACKAGE: $package_id\n";
            print_package_info($current_package);
            $changes_found = 1;
            next;
        }

        # Compare each monitored field
        my $package_changed = 0;
        foreach my $field (@MONITORED_FIELDS) {
            my $old_value = $previous_package->{$field} // 'N/A';
            my $new_value = $current_package->{$field} // 'N/A';

            # Report field changes
            if ($old_value ne $new_value) {
                if (!$package_changed) {
                    print "CHANGES in $package_id:\n";
                    $package_changed = 1;
                    $changes_found = 1;
                }
                print "  $field: '$old_value' -> '$new_value'\n";
            }
        }

        # Add spacing after package changes
        print "\n" if $package_changed;
    }

    # Check for removed repositories/packages
    foreach my $package_id (sort keys %$previous) {
        if (!exists $current->{$package_id}) {
            print "REMOVED PACKAGE: $package_id\n\n";
            $changes_found = 1;
        }
    }

    # Summary message
    if ($changes_found) {
        print "*** CHANGES DETECTED ***\n";
    } else {
        print "No changes detected since last check.\n";
    }
}

# Display current state information for a package
# Input: hashref of package data
sub print_package_info {
    my ($package_data) = @_;

    foreach my $field (@MONITORED_FIELDS) {
        my $value = $package_data->{$field} // 'N/A';
        print "  $field: $value\n";
    }
    print "\n";
}

# Display all current state information (used for first run)
# Input: hashref of all current filtered data
sub print_current_state {
    my ($current_data) = @_;

    print "Current state:\n";
    foreach my $package_id (sort keys %$current_data) {
        print "\nPackage: $package_id\n";
        print_package_info($current_data->{$package_id});
    }
}

# Execute main function
main();