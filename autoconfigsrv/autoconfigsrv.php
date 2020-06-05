<?php

/**
 * 
 * Roundcube plugin to fetch DNS SRV records following RFC 6186 and 6764 for hosts and webdav
 *
 * @license GNU GPLv3+
 * @author Ajay Singh
 */
 
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
		if(isset($_POST) && isset($_POST['_task']) && $_POST['_task']=='login' && isset($_POST['_user']) && ($regx = $rcmail->config->get('autoconfigsrv_host_regex')) && ($ehost = $this->get_ehost($_POST['_user'], $regx)) && is_array($ehost) && isset($ehost['imaps'])) {
			$args['host'] = (($rcmail->config->get('autoconfigsrv_imap_host_prefix') && $rcmail->config->get('autoconfigsrv_imap_host_prefix')!='') ? $rcmail->config->get('autoconfigsrv_imap_host_prefix') : 'ssl').'://'.$ehost['imaps'];
		}
		return $args;
	}
	
	public function smtp_connect($args) {
		$rcmail = rcmail::get_instance();
		$identity = $rcmail->user->get_identity(); 
		if(isset($identity['email']) && ($regx = $rcmail->config->get('autoconfigsrv_host_regex')) && ($ehost = $this->get_ehost($identity['email'], $regx)) && is_array($ehost) && isset($ehost['smtp'])) {
			$args['smtp_server'] = (($rcmail->config->get('autoconfigsrv_smtp_host_prefix') && $rcmail->config->get('autoconfigsrv_smtp_host_prefix')!='') ? $rcmail->config->get('autoconfigsrv_smtp_host_prefix') : 'ssl').'://'.$ehost['smtp'];
		}
		return $args;
    }
	
	public function get_ehost($email, $regex=false) {
		if((filter_var($email, FILTER_SANITIZE_EMAIL)==$email) ? filter_var($email, FILTER_VALIDATE_EMAIL) : false) {
			$host = explode("@", $email)[1];
			if($this->url_validate("http://".$host) && checkdnsrr(idn_to_ascii($host, 0, INTL_IDNA_VARIANT_UTS46), "MX")) {
				$hostd = array();
				if(($imap_r = dns_get_record('_imaps._tcp.'.$host, DNS_SRV)) && is_array($imap_r) && isset($imap_r[0]['target']) && $this->url_validate("http://".$imap_r[0]['target']) && (($regex) ? preg_match("/$regex/i", $imap_r[0]['target']) : false)) {
					$hostd['imaps'] = $imap_r[0]['target'];
				}
				if(($smtp_r = dns_get_record('_submission._tcp.'.$host, DNS_SRV)) && is_array($smtp_r) && isset($smtp_r[0]['target']) && $this->url_validate("http://".$smtp_r[0]['target']) && (($regex) ? preg_match("/$regex/i", $smtp_r[0]['target']) : false)) {
					$hostd['smtp'] = $smtp_r[0]['target'];
				}
				return $hostd;
			} else return false;
		} else return false;
	}

	public function url_validate($url) {
		if (filter_var($url, FILTER_VALIDATE_URL) === FALSE) return false;
		$url = parse_url(mb_convert_encoding(urldecode($url),'UTF-8','UTF-8'));
		if (!isset($url["host"])) return false;
		else if ($url["host"]=="localhost") return false;
		else if ($url["scheme"]!="http" && $url["scheme"]!="https") return false;
		else if (!(preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $url["host"]) && preg_match("/^.{1,253}$/", $url["host"]) && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $url["host"]))) return false;
		return (gethostbyname($url["host"]) != $url["host"]);
	}
}

