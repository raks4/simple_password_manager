#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>
#include <tuple>

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
    std::vector<std::tuple<int, std::string, std::string, std::string>>
    searchCredential(const std::string& website);

};
