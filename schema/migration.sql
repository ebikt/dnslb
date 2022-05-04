SET NAMES 'utf8';
USE `dns`;

ALTER TABLE `records` ADD COLUMN IF NOT EXISTS last_lb_check_result INT DEFAULT NULL;
