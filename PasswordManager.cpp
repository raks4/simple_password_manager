#include "PasswordManager.h"
#include "Crypto.h"
#include "Generator.h"
#include <iostream>
std::string encryptionKey;

PasswordManager::PasswordManager() : db("passwords.db") {
    db.init();
    authenticate();
}

void PasswordManager::authenticate() {
    std::string input;

    if (!db.masterExists()) {
        std::cout << "Set master password: ";
        std::cin >> input;
        db.storeMasterHash(Crypto::sha256(input));
        encryptionKey = Crypto::sha256(input);
        std::cout << "Master password set.\n";
    } else {
        std::cout << "Enter master password: ";
        std::cin >> input;

        if (Crypto::sha256(input) != db.getMasterHash()) {
            std::cout << "Authentication failed.\n";
            exit(0);
        }

        encryptionKey = Crypto::sha256(input);
    }
}

void PasswordManager::searchCredential() {

    std::string website;
    std::cout << "Enter website to search: ";
    std::cin >> website;

    auto results = db.searchCredential(website);

    if (results.empty()) {
        std::cout << "No matching credentials found.\n";
        return;
    }

    for (const auto& row : results) {
        int id;
        std::string site, user, encryptedPass;

        std::tie(id, site, user, encryptedPass) = row;

        std::string decryptedPass = Crypto::decryptAES(encryptedPass, encryptionKey);

        std::cout << id << " | " << site << " | "
                  << user << " | " << decryptedPass << "\n";
    }
}

void PasswordManager::deleteCredential() {

    int id;
    std::cout << "Enter credential ID to delete: ";
    std::cin >> id;

    db.deleteCredential(id);

    std::cout << "Credential deleted (if ID existed).\n";
}



void PasswordManager::run() {
    int choice;

    do {
        std::cout << "\n1. Add Credential\n2. View All\n3. Generate Password\n4. Search Credential\n5. Delete Credential\n6. Exit\nChoice: ";
        std::cin >> choice;

        if (choice == 1) {
            std::string website, username, password;
            std::cout << "Website: ";
            std::cin >> website;
            std::cout << "Username: ";
            std::cin >> username;
            std::cout << "Password: ";
            std::cin >> password;

            std::string encrypted =
            Crypto::encryptAES(password, encryptionKey);

            db.addCredential(website, username, encrypted);

        }

        else if (choice == 2) {
            auto creds = db.getAllCredentials();
            for (const auto& c : creds) {
                std::cout << c.id << " | "
                          << c.website << " | "
                          << c.username << " | "
                          << Crypto::decryptAES(c.password, encryptionKey) << "\n";
            }
        }

        else if (choice == 3) {
            int len;
            std::cout << "Length: ";
            std::cin >> len;
            std::cout << "Generated: "
                      << Generator::generatePassword(len) << "\n";
        }

        else if (choice == 4) {
            searchCredential();
        }

        else if (choice == 5) {
            deleteCredential();
        }

    } while (choice != 6);
}
