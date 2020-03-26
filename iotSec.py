"""Program for encryption and decryption."""

from getpass import getpass
from pathlib import Path
from Crypto.Cipher import AES
from pandas import DataFrame

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

        Step:
            1. Padding the data to make it's size 16.
            2. Create a cipher obj, which will encrypt the data using the key.
            3. Using the cipher object, encrypt the data.

        Returns:
            encrypted data (byte)
        """
        message = self._pading(message)
        cipher = AES.new(key, mode=AES.MODE_ECB)
        encrypted_text = cipher.encrypt(message)
        return encrypted_text

    def _encrypt_file(self, file_name, data=False, print_data=False):
        """
        Encrypt file.

        Steps:
            1. Open the file and read the data
            2. Encrypt the data of the files
            3. Write the data in the file

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

        Steps:
            1. Create the cipher object using the key
            2. Decrypt the data using cipher object and decode it from
               bytes to string format
            3. Remove the extra characters used while encrypting

        Returns:
            Raw data (str)
        """
        cipher = AES.new(key)
        plaintext = cipher.decrypt(cipher_text).decode('utf-8')
        return self._unpading(plaintext)

    def _decrypt_file(self, file_name, rtn_data=False, print_data=False):
        """
        Decrypt File.

        Steps:
            1. Read the file and store the encrypted data
            2. decrypt the data, using the key
            3. Write the decrypted data and store the file

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
        # with open(file_name, 'w') as f:
        #   f.write(dcrypt)

    def check_usr(self, usr, paswrd):
        """
        Authenticate user.

        Returns:
            group name or 0
        """
        data = self._decrypt_file(self.passFile, rtn_data=True)

        for line in data.strip().split('\n'):
            # print(line)
            # print(line.split(' '))
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
        data = self._decrypt_file(self.roleFile, rtn_data=True)

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
        data = self._decrypt_file(self.dataFile, rtn_data=True)
        data = data.strip().split("\n")
        data = [data[i].split(",") for i in range(len(data))]
        headers = data.pop(0)
        data = DataFrame(data, columns=headers)
        # print(headers)
        print(data[can_be_accessed])


if __name__ == '__main__':
    enc = Encryptor(key)
    # enc._encrypt_file('data.csv', print_data=True)
    # enc._decrypt_file('passwords.txt.enc', print_data=True)
    """
        Need to add more input parts
    """
    if not Path('passwords.txt.enc').is_file():
        username = input('Enter Admin Username: ')
        password = getpass('Enter Admin Password: ')
        with open('passwords.txt', 'w+') as f:
            f.write(username + ' ' + password + ' admin')
        enc._encrypt_file('passwords.txt')
        if not Path('roles.txt.enc').is_file():
            print('Enter admin roles in the form of')
            print('column1, column2, column3')
            admin_roles = input('Enter roles: ')
            with open('roles.txt', 'w+') as f:
                f.write('admin = ' + admin_roles)
            enc._encrypt_file('roles.txt')
        if not Path('data.csv').is_file():
            print('Please save your data.csv file in here')
        else:
            enc._encrypt_file('data.csv')
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
                data = enc._decrypt_file('passwords.txt', rtn_data=True)
                data = data.split('\n')
                modified = False
                for i in range(len(data)):
                    if add_data.split()[0] in data[i]:
                        data[i] = add_data
                        modified = True
                if not modified:
                    data.append(add_data)
                data = '\n'.join(data)
                with open('passwords.txt', 'w') as f:
                    f.write(data)
                enc._encrypt_file('passwords.txt')
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
                data = enc._decrypt_file('roles.txt', rtn_data=True)
                data = data.split('\n')
                modified = False
                for i in range(len(data)):
                    if add_data.split()[0] in data[i]:
                        data[i] = add_data  # replace that line with new data
                        modified = True
                if not modified:
                    data.append(add_data)
                data = '\n'.join(data)
                with open('roles.txt', 'w') as f:
                    f.write(data)
                enc._encrypt_file('roles.txt')
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
                # print(group)
                can_be_accessed = enc.get_roles(group)
                # print(can_be_accessed)
                enc.get_data(can_be_accessed)
            else:
                print('Access denied')
