DNSLB
=====

DNS Load balancer: DNS server, that changes its answers based on healtcheck results.

This is helatcheck controller. Actual DNS service is provided by PowerDNS.

Components
----------

 * PowerDNS - DNS server, reads entries from database
 * MariaDB - data backend
 * DNSLB - controller, that is executing healtchecks (this repository) and edits entries in database

Configuration
-------------

See configs/dnslb/dnslb.toml

 * FIXME: parse commandline options

Performance tuning
------------------
 * `mariadb/max_connections` >= 3 * `powerdns/receiver-threads` + 10
 * every other mariadb setting can stay low
 * `dnslb:` current implementation does not run next round of healtchecks (for given entry) before end of previous, thus `dns_timeout + timeout` should be lower than `interval`
