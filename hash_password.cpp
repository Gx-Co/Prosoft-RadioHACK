#include <iostream>
#include <string>
#include <openssl/sha.h>  // Библиотека для хеширования SHA
#include <iomanip>        // Для форматирования вывода
#include <sstream>        // Для работы со строками

std::string hashPassword(const std::string& password) {
    // Строка 1: Объявление массива для хранения хеша
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    // Строка 2: Создание контекста для хеширования
    SHA256_CTX sha256;
    
    // Строка 3: Инициализация контекста хеширования
    SHA256_Init(&sha256);
    
    // Строка 4: Добавление данных (пароля) в контекст хеширования
    SHA256_Update(&sha256, password.c_str(), password.length());
    
    // Строка 5: Завершение хеширования и получение результата
    SHA256_Final(hash, &sha256);
    
    // Строка 6: Преобразование бинарного хеша в шестнадцатеричную строку
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        // Строка 7: Запись каждого байта в виде двух шестнадцатеричных цифр
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    // Строка 8: Возврат готового хеша
    return ss.str();
}

/**
 * Функция для проверки пароля
 * @param password - проверяемый пароль
 * @param storedHash - сохраненный хеш для сравнения
 * @return true если пароль верный, false если неверный
 */
bool verifyPassword(const std::string& password, const std::string& storedHash) {
    // Строка 9: Хешируем введенный пароль и сравниваем с сохраненным хешем
    std::string inputHash = hashPassword(password);
    return inputHash == storedHash;
}

// Пример использования
int main() {
    std::string password;
    
    std::cout << "Введите пароль: ";
    std::cin >> password;
    
    // Хешируем пароль
    std::string hashedPassword = hashPassword(password);
    std::cout << "Хеш пароля: " << hashedPassword << std::endl;
    
    // Проверяем пароль
    std::cout << "Повторите пароль для проверки: ";
    std::cin >> password;
    
    if(verifyPassword(password, hashedPassword)) {
        std::cout << "Пароль верный!" << std::endl;
    } else {
        std::cout << "Пароль неверный!" << std::endl;
    }
    
    return 0;
}
