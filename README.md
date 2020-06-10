# autoconfigsrv - RC plugin to fetch DNS SRV records

Roundcube plugin to fetch DNS SRV records following RFC 6186 and 6764 for hosts and webdav. PR welcome.


# Installation

### Manual ###

1. Download, unzip, copy and rename master to 'autoconfigsrv' and paste it in 'plugins' directory of Roundcube installation. 
2. Browse folder on terminal and run 'php composer.phar update' to download dependencies.
3. Update '<roundcube installation>/config/config.inc.php' to include plugin, and configure additional options as shown below.


# Configuration

Edit `config.inc.php` file in <Your-roundcube-install-basepath>/config directory:

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

// Set true, to fetch SRV records from host domain's nameserver
$config['autoconfigsrv_use_authoritative_ns'] = false;

?>
```


# RFC Guidelines

RFC 6186 - https://tools.ietf.org/html/rfc6186

RFC 6764 - https://tools.ietf.org/html/rfc6764


# To Do

1. Follow RFC to add dav, pop3 and else
2. Use weights and priorities to handle multiple entries
