#include "Generator.h"
#include <random>

std::string Generator::generatePassword(int length) {
    const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()_+-=";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, chars.size() - 1);

    std::string password;
    for (int i = 0; i < length; ++i)
        password += chars[dist(gen)];

    return password;
}
