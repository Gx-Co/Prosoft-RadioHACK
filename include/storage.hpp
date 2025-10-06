#pragma once
#include <vector>
#include "user.hpp"

class Storage {
public:
    bool loadUsers();   // заглушка
    bool saveUsers();   // заглушка
    std::vector<User> getUsers() const { return {}; }
};
