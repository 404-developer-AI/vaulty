#!/usr/bin/env perl
# UI vocabulary scan for branding-check.sh. Prints violations on stdout and "UI_VIOLATIONS=<n>" on stderr.
use strict;
use warnings;

my $violations = 0;
my %advice = (
    "client" => "customer", "clients" => "customers",
    "device" => "the Vaulty vocabulary", "devices" => "the Vaulty vocabulary",
    "machine" => "the Vaulty vocabulary", "machines" => "the Vaulty vocabulary",
    "restore point" => "snapshot", "restore points" => "snapshots",
    "recovery point" => "snapshot", "recovery points" => "snapshots",
);

for my $file (@ARGV) {
    open(my $fh, "<", $file) or die "cannot read $file: $!";
    local $/;
    my $text = <$fh>;
    close($fh);
    # Blank out comments but keep newlines, so reported line numbers stay correct.
    my $blank = sub { my $s = shift; $s =~ s/[^\n]/ /g; return $s; };
    $text =~ s/(\@\*.*?\*\@)/$blank->($1)/gse;
    $text =~ s/(<!--.*?-->)/$blank->($1)/gse;
    $text =~ s/(\/\*.*?\*\/)/$blank->($1)/gse;
    my $number = 0;
    for my $line (split(/\n/, $text, -1)) {
        $number++;
        next if $line =~ /branding-check: ignore/;
        next if $line =~ /^\s*\@(using|inject|namespace|inherits|implements|attribute|typeparam|layout|rendermode|page)\b/;
        # C# line comments (not "://" in URLs).
        $line =~ s{(?<![:"'])//.*$}{};
        my $shown = $line;
        $shown =~ s/^\s+//;
        while ($line =~ /(?<![A-Za-z0-9_.\-\/\@])((?i:clients?|devices?|machines?|restore\s+points?|recovery\s+points?))(?![A-Za-z0-9_\-\/])/g) {
            my $word = lc($1);
            $word =~ s/\s+/ /g;
            print "$file:$number: \"$1\" in user-visible text (use $advice{$word})\n    $shown\n";
            $violations++;
        }
        if ($line =~ /(?i:teams?\s+(?:chat\s+)?messages?)/
            && $line =~ /(?<![A-Za-z0-9_.\-\/\@])(?i:restor(?:e|es|ed|ing))(?![A-Za-z0-9_\-\/])/
            && $line !~ /(?i:not\s+(?:be\s+)?restored|never\s+restored|cannot\s+be\s+restored)/) {
            print "$file:$number: Teams messages are preserved and exported, never restored\n    $shown\n";
            $violations++;
        }
    }
}
print STDERR "UI_VIOLATIONS=$violations\n";
print "branding-check: " . scalar(@ARGV) . " UI file(s) checked.\n";
