# autoconfigsrv - RC plugin to fetch DNS SRV records

Roundcube plugin is an easy fix to fetch DNS SRV records following RFC 6186 and 6764 for hosts and webdav. PR welcome.


# Installation

### 1. Composer ###

See "Getting Started" on [https://plugins.roundcube.net/](https://plugins.roundcube.net/)

Plugin name is "slickalpha/autoconfigsrv"

### 2. Manual ###

Download the folder 'autoconfigsrv' and paste it in 'plugins' directory of Roundcube installation


# Configuration

Edit `config.inc.php` file in <Your-roundcube-install-basepath>/plugins/rc_hcaptcha:

```php
<?php

// Enable plugin in config by adding the keyword to plugins array
$config['plugins'] = array('autoconfigsrv');

// Set default hosts to autoconfigsrv. Use both or either one.
$config['default_host'] = 'autoconfigsrv';
$config['smtp_server'] = 'autoconfigsrv';

// Set prefix for hosts; Default 'ssl'
$config['autoconfigsrv_imap_host_prefix'] = 'ssl';
$config['autoconfigsrv_smtp_host_prefix'] = 'tls';

// Set regex to whitelist hosts fetched from SRV records
$config['autoconfigsrv_host_regex'] = '(^[a-z0-9\.]*\.example\.com)$';

?>
```


# RFC Guidelines

RFC 6186 - https://tools.ietf.org/html/rfc6186

RFC 6764 - https://tools.ietf.org/html/rfc6764


# To Do

1. Follow RFC to add dav, pop3 and else
2. Use weights and priorities to handle multiple entries
3. Use a netdns2-like library to add option to fetch DNS record from authoritative nameservers
