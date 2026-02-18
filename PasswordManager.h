#pragma once
#include "Database.h"

class PasswordManager {
private:
    Database db;
    void authenticate();
public:
    PasswordManager();
    void run();
    void searchCredential();
    void deleteCredential();

};
