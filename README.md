DNSLB
=====

DNS Load balancer: DNS server, that changes its answers based on healtcheck
results.

This is helatcheck controller. Actual DNS service is provided by PowerDNS.

DNS Loadbalancing why and where
-------------------------------

**Why** - DNS Loadbalancing pros:

 * No loadbalancer is involved in actual connections.This prevents problems
   with NAT and routing:
   * No source port exhaustion when balancing many clients
     * Some implementations (like F5 NAT loadbalancing) may have issues arround
       ~6k connectios per second, this is related to TIME_WAIT and similar
       TCP state handling.
   * No other NAT problems (hiding client IP address, asymetric routing, …)
   * No L2 requirements (for virtual IP sharing, loadbalancer asymetrically
     forwards packets to proper MAC address)

**Where** - DNS Loadbalancing cons/requirements:

 * Actual load sharing is determined by clients, so tightly controlled
   environment is recommended (service to service communication)
 * Typical client uses `getaddrinfo`, which prefers addresses with longer
   common prefix (see RFC3484 Rule 9)
   * To prevent this, no client is allowed to be in smallest (longest) prefix
     that contains all servers. Example: servers 10.0.0.159 and 10.0.0.160
     are in prefix 10.0.0.128/26, thus no client is allowed in
     10.0.0.0 ⋯ 10.0.0.191
   * This can be turned in advantage if your goal is not loadsharing, but
     just fallback to other location.
   * Some services use `gethostbyname` which probably does not use RFC3484
     Rule 9, it is better to test your service in laboratory environment
     and/or study source code of your service.

Note: mysql/mariadb uses `getaddrinfo`.

Components
----------

 * PowerDNS - DNS server, reads entries from database
 * MariaDB - data backend
 * DNSLB - controller, that is executing healtchecks (this repository) and edits entries in database

Configuration
-------------

See configs/dnslb/dnslb.toml, which is also default location, when server is not run as user `dnslb` (`USER` environment variable),
or root (user id `0`).

Performance tuning
------------------
 * `mariadb/max_connections` >= 3 * `powerdns/receiver-threads` + 10
 * every other mariadb setting can stay low
 * `dnslb:` current implementation does not run next round of healtchecks (for given entry) before end of previous, thus `dns_timeout + timeout` should be lower than `interval`
