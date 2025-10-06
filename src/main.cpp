#include <iostream>
#include "auth.hpp"

int main() {
    std::cout << "=== Centralized Authorization Server ===" << std::endl;
    std::cout << "App started successfully!" << std::endl;

    // Заглушка: просто проверяем, что всё работает
    Auth auth;
    auth.test();

    return 0;
}
