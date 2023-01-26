import json
import os

read_file_flag = "r"
write_or_create_file_flag = "w+"
vigenere_type = "Vigenere"
caesar_type = "Caesar"
enc_file_ending = ".enc"
txt_file_ending = ".txt"
decrypt_mode = "decrypt"
encrypt_mode = "encrypt"
key_field_name = "key"
mode_field_name = "mode"
type_field_name = "type"
json_filename = 'config.json'
first_lowercase_letter = 'a'
last_lowercase_letter = 'z'
first_uppercase_letter = 'A'
last_uppercase_letter = 'Z'


letters_in_the_alphabet = 26

class CaesarCipher:
    def __init__(self, key):
        self.key = key % letters_in_the_alphabet

    def encrypt(self, to_encrypt):
        encrypted_message = ""
        for letter in to_encrypt:
            value_of_letter = ord(letter)
            if ord(first_lowercase_letter) <= value_of_letter <= ord(last_lowercase_letter):
                value_of_letter += self.key
                if value_of_letter > ord(last_lowercase_letter):
                    value_of_letter -= letters_in_the_alphabet
            elif ord(first_uppercase_letter) <= value_of_letter <= ord(last_uppercase_letter):
                value_of_letter += self.key
                if value_of_letter > ord(last_uppercase_letter):
                    value_of_letter -= letters_in_the_alphabet
            encrypted_message += chr(value_of_letter)
        return encrypted_message

    def decrypt(self, to_decrypt):
        decrypt_key = CaesarCipher(-self.key)
        return decrypt_key.encrypt(to_decrypt)


class VigenereCipher:
    def __init__(self, list_of_keys):
        self.list_of_keys = list_of_keys.copy()
        self.caesar_cipher_list = [CaesarCipher(current_key) for current_key in list_of_keys]

    def encrypt(self, to_encrypt):
        encrypted_message = ""
        current_key_index = 0
        for letter in to_encrypt:
            encrypted_message += self.caesar_cipher_list[current_key_index].encrypt(letter)
            if first_lowercase_letter <= letter <= last_lowercase_letter or first_uppercase_letter <= letter <= last_uppercase_letter:
                current_key_index += 1
                current_key_index = current_key_index % len(self.caesar_cipher_list)
        return encrypted_message

    def decrypt(self, to_decrypt):
        anti_list_of_keys = [-1 * current_key for current_key in self.list_of_keys]
        decryptVigenere = VigenereCipher(anti_list_of_keys)
        return decryptVigenere.encrypt(to_decrypt)


def getVigenereFromStr(keyString: str) -> VigenereCipher:
    list_of_keys = []
    for letter in keyString:
        value_of_letter = ord(letter)
        if ord(first_lowercase_letter) <= value_of_letter <= ord(last_lowercase_letter):
            list_of_keys.append(value_of_letter - ord(first_lowercase_letter))
        elif ord(first_uppercase_letter) <= value_of_letter <= ord(last_uppercase_letter):
            list_of_keys.append((value_of_letter - ord(first_uppercase_letter) + letters_in_the_alphabet))
    return VigenereCipher(list_of_keys)


def processDirectory(dir_path: str) -> None:
    file_dir = os.path.join(dir_path, json_filename)
    with open(file_dir) as json_file:
        data = json.load(json_file)

    action_type = data[type_field_name]
    action_mode = data[mode_field_name]
    action_key = data[key_field_name]

    for file_name in os.listdir(dir_path):
        if action_mode == encrypt_mode and file_name.endswith(txt_file_ending):
            with open(os.path.join(dir_path, file_name), read_file_flag) as current_txt_file:
                to_encrypt = current_txt_file.read()
                if action_type == caesar_type:
                    encrypted_txt = CaesarCipher(action_key).encrypt(to_encrypt)
                elif action_type == vigenere_type:
                    if isinstance(action_key, str):
                        encrypted_txt = getVigenereFromStr(action_key).encrypt(to_encrypt)
                    else:
                        encrypted_txt = VigenereCipher(action_key).encrypt(to_encrypt)
                encrypted_file_name = file_name.replace(txt_file_ending, enc_file_ending)
            with open(os.path.join(dir_path, encrypted_file_name), write_or_create_file_flag) as file_to_write:
                file_to_write.write(encrypted_txt)
        elif action_mode == decrypt_mode and file_name.endswith(enc_file_ending):
            with open(os.path.join(dir_path, file_name), read_file_flag) as current_enc_file:
                to_decrypt = current_enc_file.read()
                if action_type == caesar_type:
                    decrypted_txt = CaesarCipher(action_key).decrypt(to_decrypt)
                elif action_type == vigenere_type:
                    if isinstance(action_key, str):
                        decrypted_txt = getVigenereFromStr(action_key).decrypt(to_decrypt)
                    else:
                        decrypted_txt = VigenereCipher(action_key).decrypt(to_decrypt)
                decrypted_file_name = file_name.replace(enc_file_ending, txt_file_ending)
            with open(os.path.join(dir_path, decrypted_file_name), write_or_create_file_flag) as file_to_write:
                file_to_write.write(decrypted_txt)
