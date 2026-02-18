#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>

struct Credential {
    int id;
    std::string website;
    std::string username;
    std::string password;
};

class Database {
private:
    sqlite3* db;
public:
    Database(const std::string& db_name);
    ~Database();

    void init();
    void addCredential(const std::string& website,
                       const std::string& username,
                       const std::string& password);
    std::vector<Credential> getAllCredentials();
    bool masterExists();
    void storeMasterHash(const std::string& hash);
    std::string getMasterHash();
    void deleteCredential(int id);
    std::vector<Credential> searchByWebsite(const std::string& website);

};
