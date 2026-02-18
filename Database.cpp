#include "Database.h"
#include <iostream>

Database::Database(const std::string& db_name) {
    sqlite3_open(db_name.c_str(), &db);
}

Database::~Database() {
    sqlite3_close(db);
}

void Database::init() {
    const char* sql =
        "CREATE TABLE IF NOT EXISTS master ("
        "id INTEGER PRIMARY KEY, hash TEXT);"
        "CREATE TABLE IF NOT EXISTS credentials ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "website TEXT,"
        "username TEXT,"
        "password TEXT);";

    char* errMsg = nullptr;
    sqlite3_exec(db, sql, nullptr, nullptr, &errMsg);
}

bool Database::masterExists() {
    const char* sql = "SELECT hash FROM master LIMIT 1;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

void Database::storeMasterHash(const std::string& hash) {
    std::string sql = "INSERT INTO master (hash) VALUES (?);";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::string Database::getMasterHash() {
    const char* sql = "SELECT hash FROM master LIMIT 1;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    std::string hash;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

    sqlite3_finalize(stmt);
    return hash;
}

void Database::addCredential(const std::string& website,
                             const std::string& username,
                             const std::string& password) {
    std::string sql =
        "INSERT INTO credentials (website, username, password)"
        " VALUES (?, ?, ?);";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, password.c_str(), -1, SQLITE_STATIC);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<Credential> Database::getAllCredentials() {
    std::vector<Credential> creds;

    const char* sql = "SELECT id, website, username, password FROM credentials;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Credential c;
        c.id = sqlite3_column_int(stmt, 0);
        c.website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        c.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        c.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        creds.push_back(c);
    }

    sqlite3_finalize(stmt);
    return creds;
}

std::vector<std::tuple<int, std::string, std::string, std::string>>
Database::searchCredential(const std::string& website) {

    std::vector<std::tuple<int, std::string, std::string, std::string>> results;

    std::string sql = "SELECT id, website, username, password FROM credentials WHERE website LIKE ?;";
    sqlite3_stmt* stmt;

    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);

    std::string pattern = "%" + website + "%";
    sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_STATIC);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        std::string site = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::string user = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        std::string pass = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

        results.push_back({id, site, user, pass});
    }

    sqlite3_finalize(stmt);
    return results;
}

void Database::deleteCredential(int id) {

    std::string sql = "DELETE FROM credentials WHERE id = ?;";
    sqlite3_stmt* stmt;

    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, id);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}
