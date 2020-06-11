<?php

/**
 * 
 * Roundcube plugin to fetch DNS SRV records following RFC 6186 and 6764 for hosts and webdav
 *
 * @license GNU GPLv3+
 * @author Ajay Singh
 */

require_once __DIR__ . '/vendor/autoload.php';

class autoconfigsrv extends rcube_plugin {
	public function init() {
		$this->load_config();
		$rcmail = rcmail::get_instance();
		if ($rcmail->config->get('default_host') == 'autoconfigsrv') {
			$this->add_hook('authenticate', array($this, 'authenticate'));
		}
		if ($rcmail->config->get('smtp_server') == 'autoconfigsrv') {
			$this->add_hook('smtp_connect', array($this, 'smtp_connect'));
		}
	}

	public function authenticate($args) {
		$rcmail = rcmail::get_instance();
		if(isset($_POST) && isset($_POST['_task']) && $_POST['_task']=='login' && isset($_POST['_user']) && ($ehost = $this->get_ehost('_imaps._tcp', $_POST['_user'])) && is_array($ehost)) {
			$args['host'] = (($rcmail->config->get('autoconfigsrv_imap_host_prefix') && $rcmail->config->get('autoconfigsrv_imap_host_prefix')!='') ? $rcmail->config->get('autoconfigsrv_imap_host_prefix') : 'ssl').'://'.$ehost[0]['target'].((isset($ehost['port'])) ? ':'.$ehost['port'] : '');
		}
		return $args;
	}
	
	public function smtp_connect($args) {
		$rcmail = rcmail::get_instance();
		$identity = $rcmail->user->get_identity(); 
		if(isset($identity['email']) && ($ehost = $this->get_ehost('_submission._tcp', $identity['email'])) && is_array($ehost)) {
			$args['smtp_server'] = (($rcmail->config->get('autoconfigsrv_smtp_host_prefix') && $rcmail->config->get('autoconfigsrv_smtp_host_prefix')!='') ? $rcmail->config->get('autoconfigsrv_smtp_host_prefix') : 'ssl').'://'.$ehost[0]['target'].((isset($ehost['port'])) ? ':'.$ehost['port'] : '');
		}
		return $args;
    }
	
	public static function get_ehost($sub_r, $email) {
		$rcmail = rcmail::get_instance();
		$authoritative_ns = (($rcmail->config->get('autoconfigsrv_use_authoritative_ns') != '') ? $rcmail->config->get('autoconfigsrv_use_authoritative_ns') : false);
		$regex = ((($rcmail->config->get('autoconfigsrv_host_regex') != '') && $rcmail->config->get('autoconfigsrv_host_regex') != '') ? $rcmail->config->get('autoconfigsrv_host_regex') : false);
		if($regex===false) {
			return false;
		}
		if((filter_var($email, FILTER_SANITIZE_EMAIL)==$email) ? filter_var($email, FILTER_VALIDATE_EMAIL) : false) {
			$host = explode("@", $email)[1];
			if(self::url_validate("http://".$host) && checkdnsrr(idn_to_ascii($host, 0, INTL_IDNA_VARIANT_UTS46), "MX")) {
				$hostd = array();
				
				if($authoritative_ns!==false) {  
					require_once 'Net/DNS.php';
					if(($ns_q = dns_get_record($host, DNS_NS)) && is_array($ns_q) && isset($ns_q[0]['target'])) {
						$r = new Net_DNS_Resolver(array('nameservers' => array($ns_q[0]['target'])));
						$rec = $r->query($sub_r.'.'.$host, 'SRV');
						
						if($rec->answer && is_array($rec->answer) && count($rec->answer)>0) {
							$rdata = array();
							foreach($rec->answer as $k => $d) {
								$rdata[$k] = (array) $d;
							}
						}
						else return false;
					} else return false;
				}
				else {
					$rdata = dns_get_record($sub_r.'.'.$host, DNS_SRV);
				}
				
				if($rdata && is_array($rdata) && isset($rdata[0]['target']) && self::url_validate("http://".$rdata[0]['target']) && (($regex) ? preg_match("/$regex/i", $rdata[0]['target']) : false)) {
					return $rdata;
				} else return false;
			} else return false;
		} else return false;
	}

	public static function url_validate($url) {
		if (filter_var($url, FILTER_VALIDATE_URL) === FALSE) return false;
		$url = parse_url(mb_convert_encoding(urldecode($url),'UTF-8','UTF-8'));
		if (!isset($url["host"])) return false;
		else if ($url["host"]=="localhost") return false;
		else if ($url["scheme"]!="http" && $url["scheme"]!="https") return false;
		else if (!(preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $url["host"]) && preg_match("/^.{1,253}$/", $url["host"]) && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $url["host"]))) return false;
		return (gethostbyname($url["host"]) != $url["host"]);
	}
}

