def xor_cipher(st, key):
    originaltext_characters = list(st)

    encrypted_characters = []
    for character in originaltext_characters:
        ascii_original_value = ord(character)
        ascii_encrypted_value = key ^ ascii_original_value
        encrypted_character = chr(ascii_encrypted_value)
        encrypted_characters.append(encrypted_character)
    return ''.join(encrypted_characters)