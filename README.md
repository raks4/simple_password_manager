A Simple and Offline Password Manager written in C++. 

Uses SQLlite database to store data that is encrypted with AES.

Requires you to set a master password when the database is created and use that password everytime you would like to access the database with the CLI. This master password is secured using SHA256.

This is only a beginner project and is not fully usasble as your primary password manager yet, please use KeePassXC or other such trusted and open source software to store your passwords if you are interested in using an offline password manager seriously.

How to run:
ensure you have git and g++ from https://www.msys2.org/ for windows installed and configured to your environment variables path accordingly.

```
git clone https://github.com/raks4/simple_password_manager.git
cd simple_password_manager
g++ *.cpp -lsqlite3 -lssl -lcrypto -std=c++17 -o pm
./pm
```
