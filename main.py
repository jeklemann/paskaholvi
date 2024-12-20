#!/usr/bin/env python3

import hashlib
import json
import os
import pyaes
import sys

from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel

PBKDF2_ITERS = 500000
SALT_LEN = 32 // 8
KEY_LEN = 256 // 8


def gen_salt():
    return os.urandom(SALT_LEN // 8)


def create_default_entries(password_bytes, salt):
    key = hashlib.pbkdf2_hmac('sha3_256', password_bytes, salt, PBKDF2_ITERS)
    cipher = pyaes.AESModeOfOperationCTR(key)
    entries = json.dumps([])
    enc_entries = cipher.encrypt(entries)

    return enc_entries


def create_new_database(password):
    salt = gen_salt()
    password_bytes = password.encode()
    salted_password = password_bytes + salt
    enc_passwd = hashlib.sha3_256(salted_password).digest()

    empty_entries = create_default_entries(password_bytes, salt)
    db = Database(enc_passwd, salt, empty_entries)

    return db


class Entry:
    def __init__(self, name, url, username, enc_passwd, salt, notes):
        self.name = name
        self.url = url
        self.username = username
        self.enc_passwd = enc_passwd
        self.salt = salt
        self.notes = notes

    def decrypt_password(self, master_passwd):
        kd = hashlib.pbkdf2_hmac(
            'sha3_256',
            master_passwd.encode(),
            self.salt,
            PBKDF2_ITERS,
            KEY_LEN
        )
        return kd


class Database:
    def __init__(self, enc_passwd, salt, enc_entries):
        self.enc_passwd = enc_passwd
        self.enc_entries = enc_entries
        self.salt = salt
        self.unlocked = False
        self.entries = None
        self.passwd = None

    def lock(self):
        self.unlocked = False
        self.passwd = None

    def unlock(self, passwd):
        """
        Unlocks the database and populates the unencrypted fields.

        Returns:
            False if password is incorrect,
            None if an unexpected error occurred,
            True if successful.
        """
        salted_passwd = passwd.encode() + self.salt
        hash = hashlib.sha3_256(salted_passwd).digest()
        if hash != self.enc_passwd:
            return False

        key = hashlib.pbkdf2_hmac(
            'sha3_256',
            passwd.encode(),
            self.salt,
            PBKDF2_ITERS,
            KEY_LEN
        )

        cipher = pyaes.AESModeOfOperationCTR(key)
        dec_entries = cipher.decrypt(self.enc_entries)
        try:
            entries = json.loads(dec_entries)
        except json.JSONDecodeError:
            print("Unable to decode entries")
            return None

        self.entries = []
        for entry in entries:
            self.entries.append(Entry(**entry))

        print(entries)
        return True

    def save_to_file(self, name):
        # WIP
        save_data = {
            "enc_passwd": repr(self.enc_passwd),
            "salt": repr(self.salt),
            "enc_entries": repr(self.enc_entries)
        }

        with open(name, 'w') as file:
            json.dump(save_data, file)

    @classmethod
    def load_from_file(cls, name):
        # WIP
        with open(name, 'r') as file:
            data = json.load(file)

        return Database(
            repr(data["enc_passwd"]),
            repr(data["salt"]),
            repr(data["enc_entries"])
        )


def main():
    db = create_new_database("foobar")
    print(db.enc_entries, db.enc_passwd, db.salt)
    print(db.unlock("foobar"))
    db.save_to_file("./thefile")
    db = Database.load_from_file("./thefile")
    print(db.enc_entries, db.enc_passwd, db.salt)

    # Create the application instance
    app = QApplication(sys.argv)

    # Create the main window
    window = QMainWindow()
    window.setWindowTitle("Simple PyQt Example")
    window.setGeometry(100, 100, 400, 200)

    # Create a label widget
    label = QLabel("Hello, PyQt!", window)
    label.move(150, 80)

    # Show the window
    window.show()

    # Execute the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

