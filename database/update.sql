-- ALTER TABLE `users` ADD `account_number` VARCHAR(100) NULL AFTER `email`, ADD `account_balance` VARCHAR(100) NULL AFTER `account_number`;
-- ALTER TABLE `shops` ADD `account_number` VARCHAR(100) NULL AFTER `address`, ADD `account_balance` VARCHAR(100) NULL AFTER `account_number`;
-- ALTER TABLE `shops` DROP `citrus_seller_account`, DROP `citrus_personal_account`;
-- ALTER TABLE `users` ADD `user_name` VARCHAR(100) NULL AFTER `email`;
-- ALTER TABLE `shops` DROP `account_number`, DROP `account_balance`;
ALTER TABLE `users` ADD `sacco_name` VARCHAR(100) NULL AFTER `balance`, ADD `sacco_balance` VARCHAR(100) NULL AFTER `sacco_name`;