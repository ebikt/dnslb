SET NAMES 'utf8';
USE `dns`;

INSERT INTO domains (id, name, type) values (1, 'dnslb', 'NATIVE');
ALTER TABLE `domains` AUTO_INCREMENT = 2;

ALTER TABLE `records` ADD COLUMN last_lb_check INT DEFAULT NULL;

INSERT INTO records (domain_id, name, content, type,ttl,prio, last_lb_check)
VALUES (1,'dnslb','localhost admin.isrv.cz 1 86400 7200 604800 5','SOA',86400,NULL, -1);
