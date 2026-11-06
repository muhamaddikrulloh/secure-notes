-- Skema Database: Sistem Manajemen Catatan
-- Enkripsi Simetris AES-256-GCM + PBKDF2-HMAC-SHA256

CREATE DATABASE IF NOT EXISTS `secure_notes`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `secure_notes`;

CREATE TABLE IF NOT EXISTS `settings` (
  `id` TINYINT UNSIGNED NOT NULL PRIMARY KEY,
  `kdf_salt` VARCHAR(64) NOT NULL,
  `kdf_iterations` INT UNSIGNED NOT NULL,
  `verification_ciphertext` TEXT NOT NULL,
  `verification_nonce` VARCHAR(32) NOT NULL,
  `verification_tag` VARCHAR(32) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT `chk_single_row` CHECK (`id` = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `ui_texts` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `text_key` VARCHAR(64) NOT NULL UNIQUE,
  `ciphertext` TEXT NOT NULL,
  `nonce` VARCHAR(32) NOT NULL,
  `tag` VARCHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `notes` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `title_ciphertext` TEXT NOT NULL,
  `title_nonce` VARCHAR(32) NOT NULL,
  `title_tag` VARCHAR(32) NOT NULL,
  `content_ciphertext` MEDIUMTEXT NOT NULL,
  `content_nonce` VARCHAR(32) NOT NULL,
  `content_tag` VARCHAR(32) NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
