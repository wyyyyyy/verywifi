#!/usr/bin/perl
#use strict;
use Digest::MD5;
my $type;
my @typelist=(0x00,0x01,0x02,0x03);
my $final;


while(chomp($type = <STDIN>)&&($type != 5)){
chomp($blacklist = <STDIN>);
my $blenth=length $blacklist;
chomp($url = <STDIN>);
$url = "HTTP/1.1 301 Moved Permanently\x0d\x0alocation: ".$url."\x0d\x0aContent-type: text/html";
printf $url;
my $ulenth=length $url;
chomp($timeout = <STDIN>);
$final .= chr($typelist[$type]).chr($blenth).$blacklist.chr(2).chr($ulenth).$url.chr(3).chr(1).chr($timeout);

print "This round ends";
}

    @b = $final =~ /[\s\S]/g;
	print "\n----@b----\n";
    foreach (@b)
    {
        $d = ord($_);
        $d = $d | (0x80);
        $e .= chr($d);
    }
my $md5 = Digest::MD5->new;
$md5->add($e);
 
#printf $final."\n";
$mymd5= $md5->hexdigest;
printf $mymd5."\n";
@b = $mymd5 =~/\w{2}/g; 

my $c;
foreach $item (@b){
$c .= chr(hex($item));
}


open(filehandle2,">/home/wy/perl/b") or die "can't open file";
printf filehandle2 $c.$e;
close(filehandle2);
