"""Program for encryption and decryption."""

from getpass import getpass
from pathlib import Path
from Crypto.Cipher import AES
from pandas import DataFrame
import re

key = b'1234567890qwerty'  # size = 16


class Encryptor:
    """Encryptor class for encryption and decryption."""

    def __init__(self, key):
        """Encryptor init."""
        self.key = key
        self.passFile = 'passwords.txt'
        self.roleFile = 'roles.txt'
        self.dataFile = 'data.csv'

    def _pading(self, message):
        """
        Padding message with addition character.

        Returns:
            Paded message (str)
        """
        paded_msg = message + '$' * ((16 - len(message)) % 16)
        return paded_msg

    def _unpading(self, paded_message):
        """
        We need to remove the extra characters padded during encryption.

        Returns:
            Message (str)
        """
        message = paded_message.replace('$', '')
        return message

    def encrypt(self, message, key):
        """
        Encrypt data.

        Returns:
            encrypted data (byte)
        """
        message = self._pading(message)
        cipher = AES.new(key, mode=AES.MODE_ECB)
        encrypted_text = cipher.encrypt(message)
        return encrypted_text

    def encrypt_file(self, file_name, data=False, print_data=False):
        """
        Encrypt file.

        Returns:
            None
        """
        if not data:
            with open(file_name, 'r') as f:
                file_content = f.read()
                if print_data:
                    print(file_content)
        else:
            file_content = file_name
        encrypted_file_data = self.encrypt(file_content, self.key)
        with open(file_name + '.enc', 'wb') as f:
            f.write(encrypted_file_data)

    def decrypt(self, cipher_text, key):
        """
        Decrypt data.

        Returns:
            Raw data (str)
        """
        cipher = AES.new(key)
        plaintext = cipher.decrypt(cipher_text).decode('utf-8')
        return self._unpading(plaintext)

    def decrypt_file(self, file_name, rtn_data=False, print_data=False):
        """
        Decrypt File.

        Returns:
            None
        """
        with open(file_name + '.enc', 'rb') as f:
            cipher_text = f.read()
        dcrypt = self.decrypt(cipher_text, self.key)
        if print_data:
            print(dcrypt)
        if rtn_data:
            return dcrypt

    def check_usr(self, usr, paswrd):
        """
        Authenticate user.

        Returns:
            Group Name or 0
        """
        data = self.decrypt_file(self.passFile, rtn_data=True)

        for line in data.strip().split('\n'):
            username, password, group = line.split(' ')
            if usr == username and paswrd == password:
                return group
        return 0

    def get_roles(self, group):
        """
        Return the access allowed for the group.

        Returns:
            List of allowed access
        """
        data = self.decrypt_file(self.roleFile, rtn_data=True)

        for line in data.split('\n'):
            if group in line:
                group_name, access = line.split('=')
                return [row.strip() for row in access.split(',')]
        return 0

    def get_data(self, can_be_accessed):
        """
        Print the allowed data from the data file.

        Returns:
            None
        """
        data = self.decrypt_file(self.dataFile, rtn_data=True)
        data = data.strip().split("\n")
        data = [data[i].split(",") for i in range(len(data))]
        headers = data.pop(0)
        data = DataFrame(data, columns=headers)
        # print(headers)
        print(data[can_be_accessed])


if __name__ == '__main__':
    enc = Encryptor(key)
    if not Path('passwords.txt.enc').is_file():
        username = input('Enter Admin Username: ')
        password = getpass('Enter Admin Password: ')
        with open('passwords.txt', 'w+') as f:
            f.write(username + ' ' + password + ' admin')
        enc.encrypt_file('passwords.txt')
        Path('passwords.txt').unlink()
        if not Path('roles.txt.enc').is_file():
            print('Enter admin roles in the form of')
            print('column1, column2, column3')
            admin_roles = input('Enter roles: ')
            with open('roles.txt', 'w+') as f:
                f.write('admin = ' + admin_roles)
            enc.encrypt_file('roles.txt')
            Path('roles.txt').unlink()
        if not Path('data.csv').is_file():
            print('!!!Please save your data.csv file in here!!!')
        else:
            enc.encrypt_file('data.csv')
    else:
        usr = input('Enter Username: ')
        paswd = getpass()
        group = enc.check_usr(usr, paswd)
        if group == 'admin':
            print('1. Add/Modify Username, Password')
            print('2. Add/Modify groups or roles')
            print('3. Display data')
            choice = input('Enter Choice: ')  # Add error check here
            if choice is '1':
                print('1. Add username/password')
                print('2. Modify username/password')
                usr_choice = input('Enter Choice: ')  # Add error check here
                if usr_choice is '1':
                    add_data = input('Enter new entry in the form of:\n\
                        username password designated_group: ')
                elif usr_choice is '2':
                    add_data = input('Enter existing entry in the form of: \n\
                        username password designated_group: ')
                else:
                    print('Wrong option')
                    exit()
                data = enc.decrypt_file('passwords.txt', rtn_data=True)
                data = data.split('\n')
                modified = False
                if len(add_data.split()) != 3:
                    print('ERROR: Details not added properly. Try again!')
                    exit()
                for i in range(len(data)):
                    if add_data.split()[0] in data[i]:
                        data[i] = add_data
                        modified = True
                if not modified:
                    data.append(add_data)
                data = '\n'.join(data)
                with open('passwords.txt', 'w+') as f:
                    f.write(data)
                enc.encrypt_file('passwords.txt')
                Path('passwords.txt').unlink()
            elif choice is '2':
                print('1. Add roles')
                print('2. Modify roles')
                usr_choice = input('Enter Choice: ')  # Add error check here
                if usr_choice is '1':
                    add_data = input('Enter new role in the form of: \n\
                        group_name = column1, column2,..: ')
                elif usr_choice is '2':
                    add_data = input('Enter existing entry in the form of: \n\
                        group_name = column1, column2,..: ')
                else:
                    print('Wrong option')
                    exit()
                data = enc.decrypt_file('roles.txt', rtn_data=True)
                data = data.split('\n')
                modified = False
                regex_match_1 = re.compile('.*=.*')
                regex_match_2 = re.compile('.*=.*,.*')
                match_1 = regex_match_1.match(add_data)
                match_2 = regex_match_2.match(add_data)
                if (match_1 and match_2) is None:
                    print('ERROR: Details not added properly. Try Again!')
                    exit()
                for i in range(len(data)):
                    if add_data.split()[0] in data[i]:
                        data[i] = add_data  # replace that line with new data
                        modified = True
                if not modified:
                    data.append(add_data)
                data = '\n'.join(data)
                with open('roles.txt', 'w+') as f:
                    f.write(data)
                enc.encrypt_file('roles.txt')
                Path('roles.txt').unlink()
            elif choice is '3':
                if not Path('data.csv.enc').is_file():
                    print('Cannot process the request because \n\
                        the file does not exist')
                    exit()
                can_be_accessed = enc.get_roles(group)
                enc.get_data(can_be_accessed)
            else:
                print('Wrong option')
                exit()
        else:
            if group != 0:
                can_be_accessed = enc.get_roles(group)
                enc.get_data(can_be_accessed)
            else:
                print('Access denied')
