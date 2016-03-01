#!/usr/bin/perl
#use strict;
use Digest::MD5;
my $type;
my @typelist=(0x00,0x01,0x02,0x03,0x04,0x05);
my $final;


print ("输入规则类型\n0表示收到http响应进行重定向\n1表示白名单\n2表示期望定向到的地址\n5表示修改请求地址\n9表示退出\n");
while(chomp($type = <STDIN>)&&($type != 9)){
print ("输入正则表达式\n");
chomp($blacklist = <STDIN>);
my $blenth=length $blacklist;
print ("输入重定向后地址\n");
chomp($url = <STDIN>);
if($type == 0)
{
$url = "HTTP/1.1 301 Moved Permanently\x0d\x0alocation: ".$url."\x0d\x0aContent-type: text/html";
}
printf "重定向后填充如下内容\n".$url."\n";
my $ulenth=length $url;
print ("输入有效时间间隔，0表示始终有效\n");
chomp($timeout = <STDIN>);
$final .= chr($typelist[$type]).chr($blenth).$blacklist.chr(2).chr($ulenth).$url.chr(3).chr(1).chr($timeout);

print ("本轮规则输入完毕\n");
print ("输入规则类型,9表示退出\n");
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
