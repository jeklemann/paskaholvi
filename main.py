#!/usr/bin/env python3

import hashlib
import json
import os
import pyaes
import sys
import uuid

from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel

PBKDF2_ITERS = 500000
SALT_LEN = 32 // 8
KEY_LEN = 256 // 8


def gen_salt():
    return os.urandom(SALT_LEN)


class Entry:
    def __init__(self, id, name, url, username, enc_passwd, salt, notes):
        if id is not None:
            self.id = id
        else:
            self.id = str(uuid.uuid4())
        self.name = name
        self.url = url
        self.username = username
        self.enc_passwd = enc_passwd
        self.salt = salt
        self.notes = notes

    def decrypt_password(self, master_passwd):
        key = hashlib.pbkdf2_hmac(
            'sha3_256',
            master_passwd.encode(),
            self.salt,
            PBKDF2_ITERS,
            KEY_LEN
        )
        cipher = pyaes.AESModeOfOperationCTR(key)
        return cipher.decrypt(self.enc_passwd).decode()

    def encode(self):
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "username": self.username,
            "enc_passwd": self.enc_passwd.hex(),
            "salt": self.salt.hex(),
            "notes": self.notes
        }

    @classmethod
    def decode(cls, data):
        return cls(
            data["id"],
            data["name"],
            data["url"],
            data["username"],
            bytes.fromhex(data["enc_passwd"]),
            bytes.fromhex(data["salt"]),
            data["notes"]
        )


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
        self.entries = None

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
            self.entries.append(Entry.decode(entry))

        self.passwd = passwd.encode()
        self.unlocked = True
        return True

    def encrypt_entries(self):
        """
        Returns True if successfully encrypted, and False if vault is locked.
        """
        if not self.unlocked:
            return False

        key = hashlib.pbkdf2_hmac('sha3_256', self.passwd, self.salt, PBKDF2_ITERS)
        cipher = pyaes.AESModeOfOperationCTR(key)
        entry_dicts = []
        for entry in self.entries:
            entry_dicts.append(entry.encode())
        entries = json.dumps(entry_dicts)
        self.enc_entries = cipher.encrypt(entries)

    def add_entry(self, name, url, username, password, notes):
        """
        Returns Entry if successfully added, and None if vault is locked.
        """
        if not self.unlocked:
            return None

        salt = gen_salt()
        key = hashlib.pbkdf2_hmac('sha3_256', self.passwd, salt, PBKDF2_ITERS)
        cipher = pyaes.AESModeOfOperationCTR(key)
        enc_passwd = cipher.encrypt(password.encode())

        entry = Entry(None, name, url, username, enc_passwd, salt, notes)
        self.entries.append(entry)
        self.encrypt_entries()

        return entry

    def del_entry(self, id):
        """
        Returns True if successfully deleted,
        Returns False if vault is locked or entry is not found.
        """
        if not self.unlocked:
            return False

        index = -1
        for i in range(len(self.entries)):
            if self.entries[i].id == id:
                index = i
                break

        if index == -1:
            return False

        self.entries.pop(index)
        self.encrypt_entries()

        return True

    @classmethod
    def create_new_database(cls, password):
        salt = gen_salt()
        password_bytes = password.encode()
        salted_password = password_bytes + salt
        enc_passwd = hashlib.sha3_256(salted_password).digest()

        key = hashlib.pbkdf2_hmac('sha3_256', password_bytes, salt, PBKDF2_ITERS)
        cipher = pyaes.AESModeOfOperationCTR(key)
        entries = json.dumps([])
        enc_entries = cipher.encrypt(entries)

        db = cls(enc_passwd, salt, enc_entries)

        return db

    def save_to_file(self, name):
        save_data = {
            "enc_passwd": self.enc_passwd.hex(),
            "salt": self.salt.hex(),
            "enc_entries": self.enc_entries.hex()
        }

        with open(name, 'w') as file:
            json.dump(save_data, file)

    @classmethod
    def load_from_file(cls, name):
        with open(name, 'r') as file:
            data = json.load(file)

        return Database(
            bytes.fromhex(data["enc_passwd"]),
            bytes.fromhex(data["salt"]),
            bytes.fromhex(data["enc_entries"])
        )


def run_tests():
    db = Database.create_new_database("foobar")
    print(db.enc_entries, db.enc_passwd, db.salt)
    print(db.unlock("foobar"))
    entry = db.add_entry("bruh", "https://google.com", "yurrr", "lmaaooo", "note")
    print(entry.id)
    print(entry.decrypt_password("foobar"))
    print(db.entries)
    db.save_to_file("./thefile")
    db = Database.load_from_file("./thefile")
    print("Loaded: ", db.enc_entries, db.enc_passwd, db.salt)
    print(db.unlock("foobar"))
    print(db.del_entry(entry.id))
    print(db.entries)


def main():
    run_tests()

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

