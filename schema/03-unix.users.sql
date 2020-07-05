BEGIN;

-- PowerDNS
CREATE OR REPLACE USER     'pdns'@'localhost'   IDENTIFIED VIA 'unix_socket';
GRANT SELECT ON `dns`.* TO 'pdns'@'localhost';

-- DNSLB
CREATE OR REPLACE USER     'dnslb'@'localhost'   IDENTIFIED VIA 'unix_socket';
GRANT SELECT ON `dns`.* TO 'dnslb'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON `dns`.`records` TO 'dnslb'@'localhost';

-- Nagios
CREATE OR REPLACE USER     'nagios'@'localhost' IDENTIFIED VIA 'unix_socket';
GRANT SELECT ON `dns`.* TO 'nagios'@'localhost';

--
COMMIT;
FLUSH PRIVILEGES;
