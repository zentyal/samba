#! /usr/bin/perl

use strict;

my $file1 = shift;
my $file2 = shift;

my $seen = ();

open(FILE1,"< $file1");

while(my $line = <FILE1>) {
	if ($line =~ m/^(\S+)\s+/) {
		my $lib = $1;
		$seen->{$lib} = 1;
	}
	print $line;
}
close(FILE1);


open(FILE2,"< $file2");

while(my $line = <FILE2>) {
	if ($line =~ m/^(\S+)\s+/) {
		my $lib = $1;
		next if ($seen->{$lib});
	}
	print $line;
}
close(FILE2);


