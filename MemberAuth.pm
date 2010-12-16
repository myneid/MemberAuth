package Apache::MemberAuth;
#Written by Tanguy de Courson
#tanguy@decourson.com

use strict;
use warnings;

use Apache::Access ();
use Apache::RequestUtil ();
use Apache::RequestRec ();
use Apache::Connection ();
use APR::SockAddr;

use ModPerl::Util ();
use Apache::RequestIO ();
use Apache::Server ();
use Apache::ServerUtil ();
use APR::Table ();

use Apache::Const -compile => qw(OK REDIRECT DECLINED HTTP_UNAUTHORIZED HTTP_NOT_FOUND);

use CGI::Cookie;

use Tie::DB_Lock;
use DB_File;
use DBI;
use Data::Dumper;
my $DEBUG =0;
my $WEBAUTH =0; #do the web authentication or regular

open(WEBAUTH, "</web/webauthstatus.txt");
my $webauth_status = <WEBAUTH>;
close WEBAUTH;
if($webauth_status eq 'on')
{
	$WEBAUTH = 1;
}

sub handler
{
	my $r = shift;
	no strict 'subs';
	#$WEBAUTH=0 if($r->connection->remote_addr->ip_get eq '69.233.242.161');
	#$DEBUG=1 if($r->connection->remote_addr->ip_get eq '69.233.242.161');

	my ($status, $password) = $r->get_basic_auth_pw;
	if($DEBUG)
	{
		use Data::Dumper;
		open(LOG, ">>/tmp/auth.debug.log");
		print LOG "user: " . $r->user() . ": " . $r->connection->remote_addr->ip_get  . "\n";
		print LOG "user2: " . Apache->request->user() . "\n";
	}
	if($r->method eq 'HEAD')
	{
		#brute force programs use head to do the request for some odd reason so i'll return them a 404
		return HTTP_NOT_FOUND;
	}	
	my $siteidlist = $r->dir_config("SiteIds");
	if(!$siteidlist)
	{
		$siteidlist = '1,2';
	}
	my @ids;
	if($r->dir_config("SiteIds")  && $r->dir_config("SiteIds")  =~ /,/)
	{
		@ids = split(/,/,$r->dir_config("SiteIds"));
	}
	else
	{
		$ids[0] = $r->dir_config("SiteIds");
	}
	
	my $pw_file = $r->dir_config("AuthUserFile");
	my $user = $r->user();

	if($DEBUG)
	{
		print LOG "user3: " . $r->user() . "\n";
	}

	my $product_family = $r->dir_config("ProductFamilyId") || $ids[0];
	#AuthKey authentication, requires checking for a cookie
	my $cookies = $r->headers_in->{Cookie} || '';
	#my %cookies = CGI::Cookie->parse( $cookies );
	my @cookies = split(/;/, $cookies);
	my %cookies;
	foreach(@cookies)
	{
		my($n, $v) = split(/=/, $_);
		$n =~ s/^ //;
		$cookies{$n} = $v;
	}

	if($DEBUG)
	{
		print LOG "cookie: " . $cookies{AuthKey} . "\n";
		print LOG Dumper(%cookies);
	}
	if((!$user || $user eq '') && !$cookies{AuthKey})
	{
		if($DEBUG)
		{
			print LOG ": failed cause you was blank\n";
		}
		#unauth_page($r);
		#if($r->connection->remote_addr->ip_get eq '69.233.242.161')
		if($WEBAUTH)
		{
			my $hostname = $r->server->server_hostname();
			$hostname =~ s/members\.//;
			my $cookie = CGI::Cookie->new(-name=>'auth', -value=>'cookie on', -domain=>$hostname);
			$r->err_headers_out->add('Set-Cookie' => $cookie);
			$r->headers_out->set(Location => "http://www.$hostname/authkey_member_login.php?product_family=$product_family");
			#print "Location: http://www.$hostname/members/authkey_member_login.php?product_family=$product_family\r\n\r\n";
			return Apache::REDIRECT;
		}
		$r->note_basic_auth_failure;
		return Apache::HTTP_UNAUTHORIZED;
	}
	if($DEBUG)
	{
		print LOG "user3.1: $user\n";
	}
	if($status != Apache::OK && !($cookies{AuthKey} && $status == 401))
	{
		if($DEBUG)
		{
			print LOG "$user: $status, " . Apache::OK . "\n";
		}
		return $status;
	}
	if($DEBUG)
	{
		print LOG "user3.2: $user\n";
	}
	#return $status unless $status == Apache::OK;
	if(blocked_ip($r->connection->remote_addr->ip_get))
	{
		unauth_ip($r->connection->remote_addr->ip_get);
		if($WEBAUTH)
		{
			my $hostname = $r->server->server_hostname();
			$hostname =~ s/members\.//;
			my $cookie = CGI::Cookie->new(-name=>'auth', -value=>'cookie on', -domain=>$hostname);
			$r->err_headers_out->add('Set-Cookie' => $cookie);
			$r->headers_out->set(Location => "http://www.$hostname/members/authkey_member_login.php?product_family=$product_family&b=1");
			#print "Location: http://www.$hostname/members/authkey_member_login.php?product_family=$product_family\r\n\r\n";
			return Apache::REDIRECT;
		}
		$r->note_basic_auth_failure;
		return Apache::HTTP_UNAUTHORIZED;
	}


	#block by ip address for brute forcers


	#do a seperate cache block for authkey
	if($cookies{AuthKey} && ($user = authkey_cached($cookies{AuthKey}, $password, $product_family, $r->connection->remote_addr->ip_get)))
	{
		if($DEBUG)
		{
			print LOG "$user: cashed (authkey)\n";
		}
		$ENV{'PRODUCT_FAMILY'} = $product_family;
		return Apache::OK;
	}
	else
	{
		if(user_cached($user, $password, 'blocked', ''))
		{
			unauth_ip($r->connection->remote_addr->ip_get);
			#unauth_page();
			if($WEBAUTH)
			{
				my $hostname = $r->server->server_hostname();
				$hostname =~ s/members\.//;
				my $cookie = CGI::Cookie->new(-name=>'auth', -value=>'cookie on', -domain=>$hostname);
				$r->err_headers_out->add('Set-Cookie' => $cookie);
				$r->headers_out->set(Location => "http://www.$hostname/members/authkey_member_login.php?product_family=$product_family&b=1");
				#print "Location: http://www.$hostname/members/authkey_member_login.php?product_family=$product_family\r\n\r\n";
				return Apache::REDIRECT;
			}
			$r->note_basic_auth_failure;
			return Apache::HTTP_UNAUTHORIZED;
		}
			
		if($DEBUG)
		{
			print LOG "$user not cached ($password) (authkey)" . $r->connection->remote_addr->ip_get . "\n";
		}
	}
	#real login cache block
	if(user_cached($user, $password, $product_family, $r->connection->remote_addr->ip_get))
	{
		if($DEBUG)
		{
			print LOG "$user: cashed\n";
		}
		$ENV{'PRODUCT_FAMILY'} = $product_family;
		return Apache::OK;
	}
	else
	{
		if(user_cached($user, $password, 'blocked', ''))
		{
			unauth_ip($r->connection->remote_addr->ip_get);
			#unauth_page();
			if($WEBAUTH)
			{
				my $hostname = $r->server->server_hostname();
				$hostname =~ s/members\.//;
				my $cookie = CGI::Cookie->new(-name=>'auth', -value=>'cookie on', -domain=>$hostname);
				$r->err_headers_out->add('Set-Cookie' => $cookie);
				$r->headers_out->set(Location => "http://www.$hostname/members/authkey_member_login.php?product_family=$product_family");
				#print "Location: http://www.$hostname/members/authkey_member_login.php?product_family=$product_family\r\n\r\n";
				return Apache::REDIRECT;
			}
			$r->note_basic_auth_failure;
			return Apache::HTTP_UNAUTHORIZED;
		}
			
		if($DEBUG)
		{
			print LOG "$user not cached ($password) " . $r->connection->remote_addr->ip_get . "\n";
		}
	}

	if($DEBUG)
	{
		print LOG "user4: " . $r->user() . "\n";
	}
	#check cache
		#if good return ok
	my $sql_database = 'members';
	my $sql_host = 'mysql.localhost.com';
	my $sql_host_slave = 'slavemysql.localhost.com';
	my $sql_username = 'member';
	my $sql_password = 'member';
	my $dsn = 'DBI:mysql:database=' . $sql_database . ';' . 'host=' . $sql_host . ';' . 'port=3306' . ';mysql_client_found_rows=1';
	my $dbh = DBI->connect($dsn, $sql_username, $sql_password, { }) || die $DBI::errstr;
	my $dsn_slave = 'DBI:mysql:database=' . $sql_database . ';' . 'host=' . $sql_host_slave . ';' . 'port=3306' . ';mysql_client_found_rows=1';
	my $dbh_slave = DBI->connect($dsn_slave, $sql_username, $sql_password, { }) || die $DBI::errstr;

	if($cookies{AuthKey})
	{
		#this may be an authkey user
		if(my $user1 = mysql_authkey_valid($user, $cookies{AuthKey}, $r->dir_config("SiteIds"), $r->dir_config("ProductFamilyId"), $dbh_slave))
		{
			$user = $user1;
			if($DEBUG)
			{
				print LOG "$user: authkey user is valid\n";
			}
			#do not lock this down by ip address
			#unless it is not an auth key username which all begin with a_k
			if($user !~ /^a_k_/)
			{
				update_mysql_status(1, $dbh, $user, $r->connection->remote_addr->ip_get);
			}
			if(unsuccessful_login($dbh_slave, $user,  $r->connection->remote_addr->ip_get) && num_of_ip($dbh_slave, $user,  $r->connection->remote_addr->ip_get))
			{
				if($DEBUG)
				{
					print LOG "$user: authkey passed auth checks ($ids[0])\n";
				}
				#update_cache($user, $password, $product_family, $r->connection->remote_addr->ip_get);
				#authkey cache is different, use authkey as user and username as password
				update_cache($cookies{AuthKey}, $user, $product_family, $r->connection->remote_addr->ip_get);
				$ENV{'PRODUCT_FAMILY'} = $product_family;
				return Apache::OK;
			}
		}
		else
		{
			unauth_ip($r->connection->remote_addr->ip_get);
			if($DEBUG)
			{
				print LOG "$user: authkey not valid ($password) (" . $r->connection->remote_addr->ip_get . ")\n";
			}
			#do not lock this down by ip address
			#update_mysql_status(1, $dbh, $user, $r->connection->remote_addr->ip_get);
			#unless it is not an auth key username which all begin with a_k
			#2005-07-15: tanguy: i commented out the following lines because
			#at this point $user has nothing in it, the authkey is set but a bad authkey
			#i should probalby forward to the unauth form here
			#if($user !~ /^a_k_/)
			#{
				#update_mysql_status(0, $dbh, $user, $r->connection->remote_addr->ip_get);
			#}
		}
	}

	my $file_db_enc_pass = get_file_pass($user, $pw_file);
	if($file_db_enc_pass)
	{
		my $seed = substr($file_db_enc_pass, 0, 2);
		my $crypt_pass = crypt($password, $seed);
		my $status = 0;
		if($file_db_enc_pass eq $crypt_pass)
		{
			$status = 1;
			if($DEBUG)
			{
				print LOG "$user: good in flatfile\n";
			}
		}
		update_mysql_status($status, $dbh, $user, $r->connection->remote_addr->ip_get);
		if(($status == 1) && (unsuccessful_login($dbh_slave, $user,  $r->connection->remote_addr->ip_get) && num_of_ip($dbh_slave, $user,  $r->connection->remote_addr->ip_get)))
		{
			if($DEBUG)
			{
				print LOG "$user: passed auth checks from flat file adding to cache ($ids[0])\n";
			}
			update_cache($user, $password, $product_family, $r->connection->remote_addr->ip_get);
			$ENV{'PRODUCT_FAMILY'} = $product_family;
			return Apache::OK;
		}
		else
		{
			if($DEBUG)
			{
				print LOG "$user: failed auth checks from flat file\n";
			}
			unauth_ip($r->connection->remote_addr->ip_get);
			update_cache($user, $password, 'blocked', '');
			#unauth_page($r);
			if($WEBAUTH)
			{
				my $hostname = $r->server->server_hostname();
				$hostname =~ s/members\.//;
				my $cookie = CGI::Cookie->new(-name=>'auth', -value=>'cookie on', -domain=>$hostname);
				$r->err_headers_out->add('Set-Cookie' => $cookie);
				$r->headers_out->set(Location => "http://www.$hostname/authkey_member_login.php?product_family=$product_family&b=1");
				#print "Location: http://www.$hostname/members/authkey_member_login.php?product_family=$product_family\r\n\r\n";
				return Apache::REDIRECT;
			}
			$r->note_basic_auth_failure;
			return Apache::HTTP_UNAUTHORIZED;
		}
			
	}
	#check password file
		#if good add to cache and return ok
		#if wrong pass return unauth
	my $blocked_user = '';
	if(mysql_user_valid($user, $password, $r->dir_config("SiteIds"), $r->dir_config("ProductFamilyId"), $dbh_slave))
	{
		if($DEBUG)
		{
			print LOG "$user: mysql user is valid\n";
		}
		update_mysql_status(1, $dbh, $user, $r->connection->remote_addr->ip_get);
		if(unsuccessful_login($dbh_slave, $user,  $r->connection->remote_addr->ip_get) && num_of_ip($dbh_slave, $user,  $r->connection->remote_addr->ip_get))
		{
			if($DEBUG)
			{
				print LOG "$user: mysql passed auth checks ($ids[0])\n";
			}
			update_cache($user, $password, $product_family, $r->connection->remote_addr->ip_get);
			$ENV{'PRODUCT_FAMILY'} = $product_family;
			return Apache::OK;
		}
		else
		{
			unauth_ip($r->connection->remote_addr->ip_get);
			update_cache($user, $password, 'blocked', '');
			$blocked_user = '&b=1';
		}
	}
	else
	{
		unauth_ip($r->connection->remote_addr->ip_get);
		if($DEBUG)
		{
			print LOG "$user: mysql not valid ($password) (" . $r->connection->remote_addr->ip_get . ")\n";
		}
		update_mysql_status(0, $dbh, $user, $r->connection->remote_addr->ip_get);
	}
	#check mysql for username and password
		#if good add to cache and return ok
		#if bad return unauth
	if($DEBUG)
	{
		print LOG "$user: default decline\n";
		close LOG;
	}
	
	open(BADIPS, ">>/var/tmp/badips.txt");
	print BADIPS $r->connection->remote_addr->ip_get . "\n";
	close BADIPS;
	unauth_ip($r->connection->remote_addr->ip_get);
	#unauth_page($r);
	if($WEBAUTH)
	{
		my $hostname = $r->server->server_hostname();
		$hostname =~ s/members\.//;
		my $cookie = CGI::Cookie->new(-name=>'auth', -value=>'cookie on', -domain=>$hostname);
		$r->err_headers_out->add('Set-Cookie' => $cookie);
		$r->headers_out->set(Location => "http://www.$hostname/authkey_member_login.php?product_family=$product_family$blocked_user");
		#print "Location: http://www.$hostname/members/authkey_member_login.php?product_family=$product_family\r\n\r\n";
		return Apache::REDIRECT;
	}
	$r->note_basic_auth_failure;
	return Apache::HTTP_UNAUTHORIZED;
}
sub get_file_pass($$)
{
	my($user, $pw_file) = @_;
	#$user = Apache->request->user();
	if(!$user)
	{
		$user = '';
	}
	open(FILE, "<$pw_file") || return undef;
	while(<FILE>)
	{
		chomp();
		my($u, $p) = split(/:/, $_, 2);
		if($u eq $user)
		{
			close FILE;
			return $p;
		}
	}
	return undef;
}
sub unauth_ip($)
{
	my($ip) = @_;
	my %hash;
	tie(%hash, 'Tie::DB_Lock', "/var/tmp/passwdcache/unauth_ips.db", 'rw') || die $!;  
	$hash{$ip}++;
	untie(%hash);

}
sub blocked_ip($)
{
	my($ip) = @_;

	#since we are doing read only, make sure that if the file doesnt exist we
	#use teh access of rw to create the file
	my $access = 'r';
	if(!-e "/var/tmp/passwdcache/unauth_ips.db")
	{
		$access = 'rw';
	}
	my $max_bad_access = 15;
	my %hash;
	tie(%hash, 'Tie::DB_Lock', "/var/tmp/passwdcache/unauth_ips.db", $access) || die $!;  
	my $num;
	if($num = $hash{$ip})
	{
		if($num > $max_bad_access)
		{
			return 1;
		}
	}
	untie(%hash);

	return 0;
}
sub user_cached($$$$)
{
	my($user, $password, $id, $ip) = @_;
	#$user = Apache->request->user();
	if(!$user)
	{
		$user = '';
	}
	my %hash;
	tie(%hash, 'Tie::DB_Lock', "/var/tmp/passwdcache/$id.db", 'rw') || die $!;  
	my @tmp = split(/\./, $ip);
	my $chk_ip = '.';
	if($ip)
	{
		$chk_ip = $tmp[0] . '.' ;
		$chk_ip .= $tmp[1] if($tmp[1]);
	}

	my $key = $user . $chk_ip;
	if($DEBUG)
	{
		print LOG "user_cached(): checking ($key) ($id) (" . $hash{$key} . ")\n";
	}

	if(my $p = $hash{$key})
	{
		if($DEBUG)
		{
			print LOG "user_cached(): record found $p\n";
		}

		
		untie(%hash);
		if($p eq $password)
		{
			return $p;
			#return 1;
		}
		else
		{
			return undef;
		}
	}
	else
	{
		untie(%hash);
		return undef;
	}
	return undef;	

}
sub authkey_cached($$$$)
{
	my($user, $password, $id, $ip) = @_;
	#$user = Apache->request->user();
	if(!$user)
	{
		$user = '';
	}
	my %hash;
	tie(%hash, 'Tie::DB_Lock', "/var/tmp/passwdcache/$id.db", 'rw') || die $!;  
	my @tmp = split(/\./, $ip);
	my $chk_ip = $tmp[0] . '.' ;
	$chk_ip .= $tmp[1] if($tmp[1]);

	my $key = $user . $chk_ip;
	if($DEBUG)
	{
		print LOG "user_cached(): checking ($key) ($id) (" . $hash{$key} . ")\n";
	}

	if(my $p = $hash{$key})
	{
		if($DEBUG)
		{
			print LOG "user_cached(): record found $p\n";
		}

		
		untie(%hash);
		return $p;
	}
	else
	{
		untie(%hash);
		return undef;
	}
	return undef;	

}

sub update_cache($$$$)
{
	my($user, $password, $id, $ip) = @_;
	#$user = Apache->request->user();
	if(!$user)
	{
		$user = '';
	}
	if(!$id)
	{
		$id =0;
	}
	my %hash;
	tie(%hash, 'Tie::DB_Lock', "/var/tmp/passwdcache/$id.db", 'rw') || die $!;  
	my @tmp = split(/\./, $ip);
	my $chk_ip = '.';
	if($ip)
	{
		$chk_ip = $tmp[0] . '.' . $tmp[1];
	}
	my $key = $user . $chk_ip;
	$hash{$key} = $password;
	untie(%hash);
}
sub mysql_user_valid($$$$$)
{
	my($user, $pass, $ids, $product_family_id, $dbh) = @_;
	#$user = Apache->request->user();
	if(!$user)
	{
		$user = '';
	}

	my $sth;
	my $query;
	if(!$ids)
	{
		$ids = 1;
	}
	if($product_family_id)
	{
		$query = "select username,members.status,exp_date from members, sites, PPS.product_family as product_family where members.username=? and members.password=? and (members.Status = 'ACTIVE' OR (members.status = 'EXPIRATION' and members.exp_date >= NOW())) and ((members.SiteID=0) OR (members.SiteID = sites.SiteID and sites.product_family_id = product_family.product_family_id and product_family.product_family_id = ?) OR members.SiteID in ($ids))";
		$sth = $dbh->prepare($query);
		$sth->execute($user, $pass, $product_family_id);
	}
	else
	{
		$query = "select username,status,exp_date from members where username=? and password=? and  (members.Status = 'ACTIVE' OR (members.status = 'EXPIRATION' and members.exp_date >= NOW())) and (siteid=0 OR siteid in ($ids))";
		$sth = $dbh->prepare($query);
		$sth->execute($user, $pass);
	}

	my($u, $status, $exp_date) = $sth->fetchrow_array;
	if(!$u && $DEBUG)
	{
		print LOG "$query ($user, $pass, $product_family_id)\n";
	}
	

	
	return $u;
}
sub mysql_authkey_valid($$$$$)
{
	my($user, $pass, $ids, $product_family_id, $dbh) = @_;
	#$user = Apache->request->user();
	if(!$user)
	{
		$user = '';
	}

	my $sth;
	my $query;
	if(!$ids)
	{
		$ids = 1;
	}
	$query = "select username from members_authkeys where password=? and  date <= date_add(now(), interval 2 hour)";
	$sth = $dbh->prepare($query);
	$sth->execute($pass);

	my($u) = $sth->fetchrow_array;
	if(!$u && $DEBUG)
	{
		print LOG "$query ($user, $pass, $product_family_id)\n";
	}
	

	
	return $u;
}

sub update_mysql_status($$$$)
{
	my ($status, $dbh, $user, $ip) = @_;
	my @tmp = split(/\./, $ip);
	my $chk_ip = $tmp[0] . '.' . $tmp[1];
	
	my $query = '';
	
	if(is_auth($dbh, $user, $chk_ip))
	{
		
		$query = "UPDATE authorize set Date=NOW(), hits=hits+1 WHERE Username=? AND IP=?";
		my $sth = $dbh->prepare($query);
		$sth->execute($user, $chk_ip);
	
	} 
	else 
	{
		$query = "INSERT INTO authorize(Date,Username,IP,Status, hits) VALUES(NOW(),?,?,?, 0)";
		my $sth = $dbh->prepare($query);
		$sth->execute($user, $chk_ip, $status);
	}

}
sub is_auth($$$)
{
	my($dbh, $user, $chk_ip) = @_;

	my $query = "SELECT Username FROM authorize WHERE Username = ? AND Status = 1 AND IP=? AND Date >= date_sub(NOW(), INTERVAL 1 DAY) ";
	my $sth = $dbh->prepare($query);
	$sth->execute($user, $chk_ip);
	my($u) = $sth->fetchrow_array();
	$sth->finish();
	if($u)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
sub unsuccessful_login($$$)
{
	my ($dbh, $user, $ip) = @_;
	my @tmp = split(/\./, $ip);
	my $chk_ip = $tmp[0] . '.' . $tmp[1];

	my $max_logins = 7;
	
	my $query = "SELECT count(Username) as Num FROM authorize WHERE Username = ? AND Status = '0' AND Date >= date_sub(NOW(), INTERVAL 1 DAY) ";

	my $sth = $dbh->prepare($query);
	$sth->execute($user);
	my ($count) = $sth->fetchrow_array;
	$sth->finish();
	if(!$count)
	{
		$count =0;
	}

	if($count <= $max_logins)
	{
		return 1;
	}
	else
	{
		return 0;
	}

}
sub num_of_ip($$$)
{
	my ($dbh, $user, $ip) = @_;
	my @tmp = split(/\./, $ip);
	my $chk_ip = $tmp[0] . '.' . $tmp[1];

	my $max_ips = 17;

	my $query = "SELECT count(DISTINCT IP) as Num FROM authorize WHERE Username = ? AND Status = 1 AND Date >= date_sub(NOW(), INTERVAL 1 DAY) ";

	my $sth = $dbh->prepare($query);
	$sth->execute($user);
	my ($num) = $sth->fetchrow_array;
	$sth->finish();
	if($num <= $max_ips)
	{
		return 1;
	}
	else
	{
		return 0;
	}


}
sub unauth_page($)
{
	my $r = shift;
	if($r->connection->remote_addr->ip_get eq '69.233.242.161')
	{
		my $hostname = $r->server->server_hostname();
		my $product_family = $r->dir_config("ProductFamilyId");
		$hostname =~ s/members\.//;
		$r->headers_out->set(Location => "http://www.$hostname/authkey_member_login.php?product_family=$product_family");
		#print "Location: http://www.$hostname/members/authkey_member_login.php?product_family=$product_family\r\n\r\n";
	}

}


1;
