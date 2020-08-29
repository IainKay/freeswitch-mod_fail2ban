# mod_fail2ban
FreeSWITCH module for fail2ban

## Installing the module

`cd /usr/local/src`

`git clone https://github.com/IainKay/freeswitch-mod_fail2ban.git freeswitch-mod_fail2ban`

`cd freeswitch-mod_fail2ban`

`make && make install`


## Configuration

### Freeswitch

copy `fail2ban.conf.xml` to `/etc/freeswitch/autoload_configs/`

By default, mod_fail2ban will log to `/var/log/freeswitch/fail2ban.log`

If you need to change this, edit `fail2ban.conf.xml`


### Fail2ban


#### Jail

If you changed the log path in `fail2ban.conf.xml`, change it now so it matches.

Copy the jail template to fail2ban's config directory

`cp jail-freeswitch.conf /etc/fail2ban/jail.d/freeswitch.conf`


#### Filter

Copy the filter template to fail2ban's config directory
`cp filter-freeswitch.conf /etc/fail2ban/filter.d/freeswitch.conf`


#### Restart

Restart fail2ban
`systemctl restart fail2ban`


## Loading the module

### Manually

In `fs_cli` type `load mod_fail2ban`

### Automatically

Add `<load module="mod_fail2ban"/>` to `/etc/freeswitch/autoload_configs/modules.conf.xml`

Reload configuration

`fs_cli -x 'reloadxml'`


## Testing

An example of how we can test the regex on the command line

`fail2ban-regex '2016-08-10T14:34:09-0400 A registration failed User:1002 IP:50.149.72.66' 'A registration failed User:\d+ IP:<HOST>'`


## Precautions

[Whitelist yourself](http://www.fail2ban.org/wiki/index.php/Whitelist)


## Examples

### mod_fail2ban

`tail /var/log/freeswitch/fail2ban.log`
```
2016-08-10T17:57:54-0400 A registration was attempted User:1001 IP:50.149.72.66
2016-08-10T17:57:54-0400 A registration failed User:1001 IP:50.149.72.66
2016-08-10T17:57:54-0400 A registration was attempted User:1002 IP:50.149.72.66
2016-08-10T17:57:54-0400 A registration failed User:1002 IP:50.149.72.66
2016-08-10T17:58:03-0400 A preregistration was attempted User:1002 IP:50.149.72.66
2016-08-10T17:58:03-0400 A registration was attempted User:1002 IP:50.149.72.66
2016-08-10T17:58:03-0400 A registration failed User:1002 IP:50.149.72.66
2016-08-10T17:58:08-0400 A preregistration was attempted User:1001 IP:50.149.72.66
2016-08-10T17:58:08-0400 A registration was attempted User:1001 IP:50.149.72.66
2016-08-10T17:58:08-0400 A registration failed User:1001 IP:50.149.72.66
```

### fail2ban

`tail /var/log/fail2ban.log`
```
2016-08-10 17:46:01,439 fail2ban.jail   [23464]: INFO    Jail 'freeswitch' started
2016-08-10 17:58:09,263 fail2ban.actions[23464]: WARNING [freeswitch] Ban 50.149.72.66
2016-08-10 18:08:09,907 fail2ban.actions[23464]: WARNING [freeswitch] Unban 50.149.72.66
```

## Additional Resources
* http://www.fail2ban.org/wiki/index.php/MANUAL_0_8
* https://freeswitch.org/confluence/display/FREESWITCH/Fail2Ban
* https://freeswitch.org/confluence/display/FREESWITCH/mod_fail2ban
