#!/bin/bash

cat << __SQL__
BEGIN;

CREATE OR REPLACE USER '$USER'@'localhost' IDENTIFIED VIA 'unix_socket';
GRANT SELECT ON \`dns\`.* TO '$USER'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON \`dns\`.\`records\` TO '$USER'@'localhost';

--
COMMIT;
FLUSH PRIVILEGES;
__SQL__
