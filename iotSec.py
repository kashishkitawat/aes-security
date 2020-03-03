from Crypto.Cipher import AES

key = '1234567890qwerty'  #size = 16


class Encryptor:
    def __init__(self, key):
        self.key = key

    def _pading(self, message):
        '''
            To Encrypt, the message size should be a multiple of 16
            Hence padding required

            Returns:
                Paded message (str)
        '''
        paded_msg = message + '$'*((16-len(message))%16)
        return paded_msg

    def _unpading(self, paded_message):
        '''
            We need to remove the extra characters padded during encryption

            Returns:
                Message (str)
        '''
        message = paded_message.replace('$', '')
        return message

    def encrypt(self, message, key):
        '''
            This function encrypts the raw data.
            Step:
                1. Padding the data to make it's size 16
                2. Create a cipher object, which will encrypt the data,
                   using the key
                3. Using the cipher object, encrypt the data

            Returns:
                encrypted data (byte)
        '''
        message = self._pading(message)
        cipher = AES.new(key)
        encrypted_text = cipher.encrypt(message)
        return encrypted_text

    def encrypt_file(self, file_name):
        '''
            This function encrypts the file.
            Steps:
                1. Open the file and read the data
                2. Encrypt the data of the files
                3. Write the data in the file

            Returns:
                None
        '''
        with open(file_name, 'r') as f:
            file_content = f.read()
        encrypted_file_data = self.encrypt(file_content, self.key)
        with open(file_name + '.enc', 'w') as f:
            f.write(encrypted_file_data)

    def decrypt(self, cipherText, key):
        '''
            This function decrypts the encrypted data
            Steps:
                1. Create the cipher object using the key
                2. Decrypt the data using cipher object and decode it from
                   bytes to string format
                3. Remove the extra characters used while encrypting

            Returns:
                Raw data (str)
        '''
        cipher = AES.new(key)
        plaintext = cipher.decrypt(cipherText).decode('utf-8')
        return self._unpading(plaintext)

    def decrypt_file(self, file_name):
        '''
            This function decrypts the file
            Steps:
                1. Read the file and store the encrypted data
                2. decrypt the data, using the key
                3. Write the decrypted data and store the file

            Returns:
                None
        '''
        with open(file_name, 'r') as f:
            cipherText = f.read()
        dcrypt = self.decrypt(cipherText, self.key)
        with open(file_name[:4], 'w') as f:
            f.write(dcrypt)


enc = Encryptor(key)
msg = 'Hello World!'
print(msg)
enc_msg = enc.encrypt(msg, key)
print(enc_msg)
print(enc.decrypt(enc_msg, key))
