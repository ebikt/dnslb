DNSLB
=====

DNS Load balancer: DNS server, který mění odpovědi na základě výsledků healtchecků.

Komponenty
----------

 * PowerDNS - DNS server
 * Mysql - datový backend
 * DNSLB - controller, který spouští healtchecky (tento repozitář) a edituje databázi, kterou čte PowerDNS

Konfigurace
-----------

 * FIXME: konfigurace DNSLB je v inline v dnslb.py
 * FIXME: konfigurace a schema MYSQL je momentalne v ansible (presunout sem alespon schema)
 * FIXME: konfigurace PowerDNS je momentalne v ansible (presunout sem, mozna bez performance tuningu)

Performance tuning
------------------
 * `mysql/max_connections` >= 3 * `powerdns/receiver-threads` + 10
 * vše ostatní může být malé
 * `dnslb:` současná implementace nespustí healtchecky dokud nedoběhnou předchozí, takže se doporučuje `timeout + dns_timeout < interval`
