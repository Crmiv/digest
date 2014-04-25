<?php
	$users = array('user1'=>'asvue2a','user2'=>'axcfh8E');
	$realm = 'web';
	$username = pc_validate_digest($realm,$users);
	print "hello " .htmlentities($username);

	function pc_validate_digest($realm,$users) {
		if(!isset($_SERVER['PHP_AUTH_DIGEST'])) {
			pc_send_digest($realm);
		}
		$username = pc_parse_digest($_SERVER['PHP_AUTH_DIGEST'],$realm,$users);
		if($username === false) {
				pc_send_digest($realm);
		}
		return $username;
	}

	function pc_send_digest($realm) {
		header('HTTP/1.0 401 Unauthorized');
		$nonce = md5(uniqid());
		$opaque = md5($realm);
		header("WWW-Authenticate: Digest realm=\"$realm\" qop=\"auth\" ".
				"nonce=\"$nonce\" opaque=\"$opaque\"");
		echo "you need valid user password";
		exit;
	}

	function pc_parse_digest($digest, $realm, $users) {
		$digest_info = array();
		foreach(array('username','uri','nonce','cnonce','response') as $part) {
			if(preg_match('/'.$part.'=([\? "]?)(.*?)\1/',$digest,$match)) {
				$digest_info['part'] = $match[2];
			}else{
			return false;
			}
		}
		if(preg_match('/qop=auth(,|$)/',$digest)) {
			$digest_info['qop'] = 'auth';
		} else {
			return false;
		}

		if(preg_match('/nc=([0-9a-f]{8})(,|$)/',$digest,$match)) {
			$digest_info['nc'] = $match[1];
		}else {
			return false;
		}

		$A1 = $digest_info['username'] . ':' .$realm . ':' .$users[digest_info['username']];
		$A2 = $_SERVER['REQUEST_METHOD'] . ':' . $digest_info['uri'];
		$request_digest = md5(implode(':',array(md5($A1),$digest_info['nonce'],$digest_info['nc'],
			$digest_info['cnonce'],$digest_info['qop'],md5($A2))));
		
		if($request_digest != $digest_info['response']) {
			return false;
		}
		return $digest info['username'];
	}

?>
