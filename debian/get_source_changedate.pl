#! /usr/bin/perl

use strict;
use Dpkg::Changelog::Parse;
use Data::Dumper;

my %opts = ("file" => 'debian/changelog');

# get last changelog entry
my $entry = changelog_parse(%opts);

# if binnmu: get previous entry, which is the source entry
if ($entry->{"Binary-Only"}) {
	$opts{"count"} = 1;
	$opts{"offset"} = 1;
	$entry = changelog_parse(%opts);
}

# get the last change date for the source entry
my $source_date = $entry->{"Date"};
print "$source_date\n";
