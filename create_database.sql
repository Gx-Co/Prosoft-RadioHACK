-- Создание базы данных
CREATE DATABASE IF NOT EXISTS users_db;
USE users_db;

-- Создание таблицы пользователей
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_key VARCHAR(50) UNIQUE NOT NULL,
    login VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'engineer', 'assistant') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Создание индексов для быстрого поиска
CREATE INDEX idx_login ON users(login);
CREATE INDEX idx_key ON users(user_key);
CREATE INDEX idx_role ON users(role);

-- Вставка тестовых данных
INSERT INTO users (user_key, login, password_hash, role) VALUES
('KEY001', 'admin_user', 'hash_admin123', 'admin'),
('KEY002', 'engineer_john', 'hash_engineer123', 'engineer'),
('KEY003', 'assistant_mary', 'hash_assistant123', 'assistant');
