#include <iostream>
#include <string>
#include <vector>
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

class DatabaseManager {
private:
    sql::mysql::MySQL_Driver* driver;
    std::unique_ptr<sql::Connection> connection;
    
    // Хеширование пароля
    std::string hashPassword(const std::string& password) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, password.c_str(), password.length());
        SHA256_Final(hash, &sha256);
        
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

public:
    DatabaseManager() : driver(nullptr) {}
    
    // Подключение к базе данных
    bool connect(const std::string& host, const std::string& user, 
                 const std::string& password, const std::string& database) {
        try {
            driver = sql::mysql::get_mysql_driver_instance();
            connection.reset(driver->connect(host, user, password));
            connection->setSchema(database);
            std::cout << "Успешное подключение к базе данных!" << std::endl;
            return true;
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка подключения: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Добавление новой записи
    bool addUser(const std::string& key, const std::string& login, 
                 const std::string& password, const std::string& role) {
        try {
            std::string password_hash = hashPassword(password);
            
            std::unique_ptr<sql::PreparedStatement> pstmt(
                connection->prepareStatement(
                    "INSERT INTO users (user_key, login, password_hash, role) VALUES (?, ?, ?, ?)"
                )
            );
            
            pstmt->setString(1, key);
            pstmt->setString(2, login);
            pstmt->setString(3, password_hash);
            pstmt->setString(4, role);
            
            pstmt->executeUpdate();
            std::cout << "Пользователь добавлен успешно!" << std::endl;
            return true;
            
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка добавления пользователя: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Поиск пользователя по логину
    bool findUserByLogin(const std::string& login) {
        try {
            std::unique_ptr<sql::PreparedStatement> pstmt(
                connection->prepareStatement(
                    "SELECT user_key, login, role FROM users WHERE login = ?"
                )
            );
            
            pstmt->setString(1, login);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
            
            if (res->next()) {
                std::cout << "Найден пользователь:" << std::endl;
                std::cout << "Ключ: " << res->getString("user_key") << std::endl;
                std::cout << "Логин: " << res->getString("login") << std::endl;
                std::cout << "Роль: " << res->getString("role") << std::endl;
                return true;
            } else {
                std::cout << "Пользователь с логином '" << login << "' не найден." << std::endl;
                return false;
            }
            
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка поиска: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Проверка пароля
    bool verifyPassword(const std::string& login, const std::string& password) {
        try {
            std::string input_hash = hashPassword(password);
            
            std::unique_ptr<sql::PreparedStatement> pstmt(
                connection->prepareStatement(
                    "SELECT password_hash FROM users WHERE login = ?"
                )
            );
            
            pstmt->setString(1, login);
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
            
            if (res->next()) {
                std::string stored_hash = res->getString("password_hash");
                if (input_hash == stored_hash) {
                    std::cout << "Пароль верный!" << std::endl;
                    return true;
                } else {
                    std::cout << "Неверный пароль!" << std::endl;
                    return false;
                }
            } else {
                std::cout << "Пользователь не найден!" << std::endl;
                return false;
            }
            
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка проверки пароля: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Обновление записи
    bool updateUser(const std::string& key, const std::string& new_login = "",
                    const std::string& new_password = "", const std::string& new_role = "") {
        try {
            std::string query = "UPDATE users SET ";
            std::vector<std::string> updates;
            
            if (!new_login.empty()) updates.push_back("login = ?");
            if (!new_password.empty()) updates.push_back("password_hash = ?");
            if (!new_role.empty()) updates.push_back("role = ?");
            
            for (size_t i = 0; i < updates.size(); ++i) {
                query += updates[i];
                if (i < updates.size() - 1) query += ", ";
            }
            query += " WHERE user_key = ?";
            
            std::unique_ptr<sql::PreparedStatement> pstmt(
                connection->prepareStatement(query)
            );
            
            int param_index = 1;
            if (!new_login.empty()) pstmt->setString(param_index++, new_login);
            if (!new_password.empty()) pstmt->setString(param_index++, hashPassword(new_password));
            if (!new_role.empty()) pstmt->setString(param_index++, new_role);
            pstmt->setString(param_index, key);
            
            int affected_rows = pstmt->executeUpdate();
            if (affected_rows > 0) {
                std::cout << "Запись обновлена успешно!" << std::endl;
                return true;
            } else {
                std::cout << "Запись с ключом '" << key << "' не найдена." << std::endl;
                return false;
            }
            
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка обновления: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Удаление записи
    bool deleteUser(const std::string& key) {
        try {
            std::unique_ptr<sql::PreparedStatement> pstmt(
                connection->prepareStatement(
                    "DELETE FROM users WHERE user_key = ?"
                )
            );
            
            pstmt->setString(1, key);
            int affected_rows = pstmt->executeUpdate();
            
            if (affected_rows > 0) {
                std::cout << "Запись удалена успешно!" << std::endl;
                return true;
            } else {
                std::cout << "Запись с ключом '" << key << "' не найдена." << std::endl;
                return false;
            }
            
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка удаления: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Показать всех пользователей
    void showAllUsers() {
        try {
            std::unique_ptr<sql::Statement> stmt(connection->createStatement());
            std::unique_ptr<sql::ResultSet> res(
                stmt->executeQuery("SELECT user_key, login, role FROM users ORDER BY id")
            );
            
            std::cout << "\n=== Все пользователи ===" << std::endl;
            while (res->next()) {
                std::cout << "Ключ: " << res->getString("user_key")
                          << " | Логин: " << res->getString("login")
                          << " | Роль: " << res->getString("role") << std::endl;
            }
            std::cout << "========================\n" << std::endl;
            
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка получения списка: " << e.what() << std::endl;
        }
    }
};

// Функция для отображения меню
void showMenu() {
    std::cout << "\n=== Меню управления базой данных ===" << std::endl;
    std::cout << "1. Добавить пользователя" << std::endl;
    std::cout << "2. Найти пользователя по логину" << std::endl;
    std::cout << "3. Проверить пароль" << std::endl;
    std::cout << "4. Обновить пользователя" << std::endl;
    std::cout << "5. Удалить пользователя" << std::endl;
    std::cout << "6. Показать всех пользователей" << std::endl;
    std::cout << "7. Выход" << std::endl;
    std::cout << "Выберите действие: ";
}

int main() {
    DatabaseManager db;
    
    // Подключение к базе данных
    if (!db.connect("tcp://127.0.0.1:3306", "root", "password", "users_db")) {
        return 1;
    }
    
    int choice;
    std::string key, login, password, role;
    
    while (true) {
        showMenu();
        std::cin >> choice;
        std::cin.ignore(); // Очистка буфера
        
        switch (choice) {
            case 1: // Добавить пользователя
                std::cout << "Введите ключ: ";
                std::getline(std::cin, key);
                std::cout << "Введите логин: ";
                std::getline(std::cin, login);
                std::cout << "Введите пароль: ";
                std::getline(std::cin, password);
                std::cout << "Введите роль (admin/engineer/assistant): ";
                std::getline(std::cin, role);
                db.addUser(key, login, password, role);
                break;
                
            case 2: // Найти по логину
                std::cout << "Введите логин для поиска: ";
                std::getline(std::cin, login);
                db.findUserByLogin(login);
                break;
                
            case 3: // Проверить пароль
                std::cout << "Введите логин: ";
                std::getline(std::cin, login);
                std::cout << "Введите пароль для проверки: ";
                std::getline(std::cin, password);
                db.verifyPassword(login, password);
                break;
                
            case 4: // Обновить пользователя
                std::cout << "Введите ключ пользователя для обновления: ";
                std::getline(std::cin, key);
                std::cout << "Введите новый логин (или Enter чтобы пропустить): ";
                std::getline(std::cin, login);
                std::cout << "Введите новый пароль (или Enter чтобы пропустить): ";
                std::getline(std::cin, password);
                std::cout << "Введите новую роль (или Enter чтобы пропустить): ";
                std::getline(std::cin, role);
                db.updateUser(key, 
                    login.empty() ? "" : login,
                    password.empty() ? "" : password,
                    role.empty() ? "" : role);
                break;
                
            case 5: // Удалить пользователя
                std::cout << "Введите ключ пользователя для удаления: ";
                std::getline(std::cin, key);
                db.deleteUser(key);
                break;
                
            case 6: // Показать всех
                db.showAllUsers();
                break;
                
            case 7: // Выход
                std::cout << "Выход из программы." << std::endl;
                return 0;
                
            default:
                std::cout << "Неверный выбор!" << std::endl;
        }
    }
    
    return 0;
}
