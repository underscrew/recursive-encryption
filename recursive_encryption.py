import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode
import zlib


def _derive_key(password: bytes, salt: bytes,
                iterations: int = 100_000) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(), length=32, salt=salt,
        iterations=iterations, backend=default_backend())
    return b64e(kdf.derive(password))


def password_encrypt(message: bytes, password: str, iterations: int = 100_000,
                     compress: bool = True) -> bytes:
    '''Encrypt a message with a given password'''
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    token = (
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            (Fernet(key).encrypt(message)),
        )
    )
    return zlib.compress(token, 9) if compress else token


def password_decrypt(token: bytes, password: str, compressed=True) -> bytes:
    '''Decrypt a message with a given password'''
    if compressed:
        decoded = zlib.decompress(token)
    salt, iter, token = decoded[:16], decoded[16:20], (decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def encrypt_with_questions(questions: list, my_data: str,
                           sep: str = ':end:') -> bytes:
    '''Recursively encrypt the data and
    the next questions with the given answer'''
    my_data = my_data.encode('latin-1')
    questions = list(map(lambda x: (x+sep).encode('latin-1'), questions))
    for question in questions:
        my_password = input(f'Answer to encrypt this:\n'
                            f'{(question+b"...").decode("latin-1")} \n')
        my_data = question+my_data
        my_data = password_encrypt(my_data, my_password)
    return my_data


def generate_qr(data_to_insert: list, qr_size: int = 30,
                filename: str = "encrypted.jpg"):
    '''Generates an QR Code containing the '''
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=qr_size,
        border=0,
    )
    for data in data_to_insert:
        qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)


def decrypt_recursively(encrypted_data: bytes) -> tuple:
    '''Iterates the decryption until the leftover data is decodable'''
    while True:
        my_password = input('Insert the password(answer) \n')
        try:
            encrypted_data = password_decrypt(encrypted_data, my_password)
            question, encrypted_data = encrypted_data.split(sep.encode())
            try:
                decrypted = encrypted_data.decode()
                last_message = question.decode("latin-1")
                print('\nDone! Decrypted!')
                print(f'Encrypted to:{decrypted}')
                print(f'Got the last message:{decrypted}')
                return last_message, decrypted
            except:
                print('Correct answer! Keep on!')
                print(f'The question is {question.decode("latin-1")}')
        except:
            print('Wrong password!')


qr_size = 30
my_data = "some very important secret, like a secret key"

# Separator to be between the questions and the secrets
sep = ':end:'

# Set the question to be visible with the qrcode
open_question = 'Message within the qrcode, like question 0'

# Set the questions to be recursively encrypted
questions = []
questions.append('message within the data')
questions.append('last question')
questions.append('before last')
questions.append('second question')
questions.append('first question')

# Do the important stuff
encrypted_data = encrypt_with_questions(questions, my_data)

# Just to store, not necessary
# Haven't found an android scanner for mixed type data :(
encoded_encrypted_data = b64e(encrypted_data)

# You can store the recursively encrypted data to a file
with open("encoded_encrypted_data.b64", "wb") as text_file:
    text_file.write(open_question.encode()+b'\n')
    text_file.write(encoded_encrypted_data)
with open("encoded_encrypted_data.b64", "rb") as text_file:
    open_question_, encoded_encrypted_data = text_file.readlines()

assert open_question==open_question_.decode()[:-1]
assert encrypted_data == b64d(encoded_encrypted_data)

# You can also store the recursively encrypted data to a qrcode
generate_qr([open_question, sep, encoded_encrypted_data])

# Finally decrypt it
last_message, decrypted = decrypt_recursively(b64d(encoded_encrypted_data))

assert last_message == questions[0]
assert decrypted == my_data
