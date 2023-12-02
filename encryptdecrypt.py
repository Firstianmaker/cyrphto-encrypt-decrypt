# Import Blowfish library
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
# Import TripleDes library
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
# Import RSA library
import rsa
# Import streamlit library
import streamlit as st
import base64

# Set page configuration
st.set_page_config(
    page_title="Cryptograph Encrypt Decreypt",
    page_icon="🔐",
    layout='wide'
)

                                                                              # Welcome Page #
def welcome_page():
    st.title("Welcome to Cryptograph Encrypt Decrypt")
    st.markdown(
        """
        Hello! Welcome to our application. This application can be used to encrypt and decrypt messages using various algorithms.
        """
    )
  
    with st.expander("Encryption"):
        st.markdown("""
            Encryption is the process of converting information or data into a code to prevent unauthorized access. 
            It involves using an algorithm (encryption key) to transform the original data into an unreadable format, known as ciphertext.
        """)

    with st.expander("Decryption"):
        st.markdown("""
            Decryption is the process of converting encrypted data or ciphertext back into its original, readable format. 
            It involves using a decryption key or algorithm to reverse the encryption process.
        """)

    with st.expander("About us"):
        st.markdown("""
        Team 8:
            - 2210511045 - Faiz Firstian Nugroho
            - 2210511049 - Daffa Andika Firmansyah
            - 2210511061 - Rofief Amanulloh
            - 2210511076 - Othman Hanif Wiradharma
            - 2210511080 - Muhammad Reza Adi Pratama
        """
        )

                                                                            # RSA #

def rsa_page():
    st.title("RSA Cryptography")
    st.header("Encrypt and Decrypt a message using RSA algorithm")

    with st.expander("What is RSA?"):
        st.markdown("""
            RSA is the first asymmetric cryptography algorithm used for encryption and digital signatures. 
            RSA stands for Rivest-Shamir-Adleman, the creators of the algorithm. 
            RSA is based on factorization, which means that the public key and private key are related to each other through a factorization function.
        """)

    col1, col2 = st.columns(2)

    # Encryption UI
    with col1:
        with st.form(key="encrypt"):
            st.subheader("Encrypt a message")
            key_length = st.selectbox("Select length of key", [256, 512, 1024, 2048, 3072, 4096])
            text = st.text_area("Enter a message")

            submit = st.form_submit_button(label="Encrypt")

        @st.cache_data
        def generate_key(length):
            return rsa.newkeys(length, accurate=True)

        (public_key, private_key) = generate_key(key_length)

        @st.cache_data
        def encrypt_message(text: str, _public_key):
            return rsa.encrypt(text.encode(), _public_key)

        # Encrypt message
        if submit:
            try:
                encrypted_message = encrypt_message(text, public_key)
                st.write("Encrypted message: ", encrypted_message.hex())

                private_key_copy = private_key.save_pkcs1().hex()
                st.text_area("Private key", value=private_key_copy, height=150, disabled=True)

            except:
                st.warning("Message too large, please enter a smaller message or use a larger key. Key with Length {} can only encrypt {} characters".format(key_length, key_length // 8 - 11))

    # Decryption UI
    with col2:
        with st.form(key="decrypt"):
            st.subheader("Decrypt a message")
            encrypt_message_input = st.text_area("Enter encrypted message")
            private_key_input = st.text_area("Enter private key", disabled=False)
            submit1 = st.form_submit_button(label="Decrypt")

        # Decrypt message
        if encrypt_message_input == "":
            st.warning("Please enter a message to decrypt")

        try:
            if private_key_input == "":
                st.warning("Please enter private key")
            else:
                private_key_input = rsa.PrivateKey.load_pkcs1(bytes.fromhex(private_key_input))
                decrypt_message = rsa.decrypt(bytes.fromhex(encrypt_message_input), private_key_input)
                st.write("Decrypted message: ", decrypt_message.decode())
                st.cache_data.clear()
        except:
            st.warning("Please enter a valid encrypted message or check the length of the key")

    st.info("Setiap kali melakukan enkripsi, key akan digenerate secara otomatis. Silakan copy private key untuk melakukan dekripsi.")

    with st.expander("About us"):
        st.markdown("""
        Team 8:
            - 2210511045 - Faiz Firstian Nugroho
            - 2210511049 - Daffa Andika Firmansyah
            - 2210511061 - Rofief Amanulloh
            - 2210511076 - Othman Hanif Wiradharma
            - 2210511080 - Muhammad Reza Adi Pratama
        """
        )




                                                                    # TripleDes #
# Define a simple Session State to store the encrypted message
class SessionState:
    def __init__(self):
        self.encrypted_message = None

# Create a Session State object
session_state = SessionState()

def triple_des_encrypt(message, key, key2, key3, mode='EEE'):
    key = key.ljust(24)
    key2 = key2.ljust(24)
    key3 = key3.ljust(24)
    cipher1 = DES3.new(key.encode(), DES3.MODE_ECB)
    cipher2 = DES3.new(key2.encode(), DES3.MODE_ECB)
    cipher3 = DES3.new(key3.encode(), DES3.MODE_ECB)
    block_size = 8
    padded_message = message + ' ' * (block_size - len(message) % block_size)

    if mode == 'EEE':
        encrypted_message = cipher1.encrypt(padded_message.encode())
        encrypted_message = cipher2.encrypt(encrypted_message)
        encrypted_message = cipher3.encrypt(encrypted_message)
    elif mode == 'EDE':
        encrypted_message = cipher1.encrypt(padded_message.encode())
        encrypted_message = cipher2.decrypt(encrypted_message)
        encrypted_message = cipher3.encrypt(encrypted_message)
    else:
        raise ValueError("Mode must be 'EEE' or 'EDE'")
    
    encoded_message = base64.b64encode(encrypted_message).decode()
    return encoded_message

def triple_des_decrypt(encoded_message, key, key2, key3, mode='EEE'):
    key = key.ljust(24)
    key2 = key2.ljust(24)
    key3 = key3.ljust(24)
    cipher1 = DES3.new(key.encode(), DES3.MODE_ECB)
    cipher2 = DES3.new(key2.encode(), DES3.MODE_ECB)
    cipher3 = DES3.new(key3.encode(), DES3.MODE_ECB)
    encrypted_message = base64.b64decode(encoded_message)

    if mode == 'EEE':
        decrypted_message = cipher3.decrypt(encrypted_message)
        decrypted_message = cipher2.decrypt(decrypted_message)
        decrypted_message = cipher1.decrypt(decrypted_message)
    elif mode == 'EDE':
        decrypted_message = cipher3.decrypt(encrypted_message)
        decrypted_message = cipher2.encrypt(decrypted_message)
        decrypted_message = cipher1.decrypt(decrypted_message)
    else:
        raise ValueError("Mode must be 'EEE' or 'EDE'")
    
    decrypted_message = decrypted_message.decode()
    return decrypted_message

def triple_des_page():
    st.title("TripleDes Cryptography")
    st.header("Encrypt and Decrypt a message using Triple Des algorithm")

    with st.expander("What is TripleDes?"):
        st.markdown("""
            Triple DES (Triple Data Encryption Standard) is an enhancement of DES (Data Encryption Standard) that uses three key blocks to improve encryption security. 
            This algorithm performs encryption three times on the same data block using three different keys. 
            Triple DES achieves additional security with a longer key length (168 bits).
        """)

    col1, col2 = st.columns(2)

    # Encryption UI
    with col1:
        with st.form(key="encrypttriple"):
            st.subheader("🔒 Enkripsi")
            st.write("Masukkan kalimat yang akan dienkripsi:")

            message = st.text_input("Kalimat:")
            key = st.text_input("Kata Kunci Enkripsi Pertama (Panjang: 9-24) :")
            key2 = st.text_input("Kata Kunci Enkripsi Kedua (Panjang: 9-24) :")
            key3 = st.text_input("Kata Kunci Enkripsi Ketiga (Panjang: 9-24) :")
            mode = st.selectbox("Pilih Mode Enkripsi:", ['EEE', 'EDE'])

            submit_encrypt = st.form_submit_button("Enkripsi")
            if submit_encrypt:
                if not message or not key or not key2 or not key3:
                    st.warning("Masukkan kalimat dan ketiga kunci enkripsi terlebih dahulu.")
                else:
                    encrypted_message = triple_des_encrypt(message, key, key2, key3, mode)
                    session_state.encrypted_message = encrypted_message  # Store encrypted message
                    st.success(f"Hasil enkripsi kalimat input adalah:\n{encrypted_message}")

    # Decryption UI
    with col2:
        with st.form(key="decrypttriple"):
            st.subheader("🔓 Dekripsi")
            st.write("Masukkan kalimat yang akan didekripsi:")

            decrypt_message = st.text_input("Kalimat Terenkripsi:")
            decrypt_key = st.text_input("Kata Kunci Enkripsi Pertama (Panjang: 9-24) :")
            decrypt_key2 = st.text_input("Kata Kunci Enkripsi Kedua (Panjang: 9-24) :")
            decrypt_key3 = st.text_input("Kata Kunci Enkripsi Ketiga (Panjang: 9-24) :")
            decrypt_mode = st.selectbox("Pilih Mode Dekripsi:", ['EEE', 'EDE'])

            submit_decrypt = st.form_submit_button("Dekripsi")
            if submit_decrypt:
                if not decrypt_message or not decrypt_key or not decrypt_key2 or not decrypt_key3:
                    st.warning("Masukkan kalimat terenkripsi dan ketiga kunci enkripsi terlebih dahulu.")
                else:
                    encrypted_message = session_state.encrypted_message  # Retrieve encrypted message
                    decrypted_message = triple_des_decrypt(encrypted_message, decrypt_key, decrypt_key2, decrypt_key3, decrypt_mode)
                    st.success(f"Hasil dekripsi dari kalimat terenkripsi adalah:\n{decrypted_message}")

    with st.expander("About us"):
        st.markdown("""
        Team 8:
            - 2210511045 - Faiz Firstian Nugroho
            - 2210511049 - Daffa Andika Firmansyah
            - 2210511061 - Rofief Amanulloh
            - 2210511076 - Othman Hanif Wiradharma
            - 2210511080 - Muhammad Reza Adi Pratama
        """
        )


                                                            # Blowfish #
def blowfish_page():
    st.title("Blowfish Cryptography")

    st.header("Encrypt and Decrypt a message using Blowfish algorithm")

    with st.expander("What is Blowfish?"):
        st.markdown("""
            Blowfish is a symmetric-key block cipher that can be used for encryption and decryption. 
            It is designed to be fast and secure. Blowfish operates on fixed-size blocks of data (64 bits) 
            and supports key sizes from 32 bits to 448 bits.
        """)

    with st.expander("Apa itu Blowfish?"):
        st.markdown("""
            Blowfish adalah cipher blok kunci simetris yang dapat digunakan untuk enkripsi dan dekripsi. 
            Ini dirancang untuk menjadi cepat dan aman. 
            Blowfish beroperasi pada blok data dengan ukuran tetap (64 bit) dan mendukung ukuran kunci dari 32 bit hingga 448 bit.
        """)

    # Encryption Section
    st.subheader("Encrypt a message")
    text = st.text_area("Enter a message")
    key = st.text_input("Enter encryption key 🔑", type="password")

    if st.button("Encrypt"):
        if text == "":
            st.warning("Please enter a message to encrypt")
        elif key == "":
            st.warning("Please enter an encryption key")
        else:
            cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
            encrypted_bytes = cipher.encrypt(pad(text.encode(), Blowfish.block_size))
            encrypted_message = encrypted_bytes.hex()
            st.success("Encrypted message")
            st.info(encrypted_message)

    # Decryption Section
    st.subheader("Decrypt a message")
    encrypted_message_input = st.text_area("Enter encrypted message")
    key_input = st.text_input("Enter decryption key 🔑", type="password")

    if st.button("Decrypt"):
        if encrypted_message_input == "":
            st.warning("Please enter a message to decrypt")
        elif key_input == "":
            st.warning("Please enter a decryption key")
        else:
            try:
                cipher = Blowfish.new(key_input.encode(), Blowfish.MODE_ECB)
                decrypted_bytes = unpad(cipher.decrypt(bytes.fromhex(encrypted_message_input)), Blowfish.block_size)
                decrypted_message = decrypted_bytes.decode()
                st.success("Decrypted message")
                st.info(decrypted_message)
            except Exception as e:
                st.warning("Error during decryption: {}".format(str(e)))

    st.info("Please keep the encryption and decryption keys secure. They are crucial for data security.")

    # Information Section in Sidebar
    with st.expander("About us"):
        st.markdown("""
        Team 8:
            - 2210511045 - Faiz Firstian Nugroho
            - 2210511049 - Daffa Andika Firmansyah
            - 2210511061 - Rofief Amanulloh
            - 2210511076 - Othman Hanif Wiradharma
            - 2210511080 - Muhammad Reza Adi Pratama
        """
        )

                                            # Caesar Cypher #

def caesar_encrypt(message, shift):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            if char.isupper():
                encrypted_message += chr((ord(char) + shift - ord('A')) % 26 + ord('A'))
            else:
                encrypted_message += chr((ord(char) + shift - ord('a')) % 26 + ord('a'))
        else:
            encrypted_message += char
    return encrypted_message

def caesar_decrypt(encrypted_message, shift):
    return caesar_encrypt(encrypted_message, -shift)

def caesar_page():
    st.title("Caesar Cipher")
    st.header("Encrypt and Decrypt a message using Caesar Cipher algorithm")

    with st.expander("What is Caesar Cipher?"):
        st.markdown("""
            Caesar Cipher is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.
            In this implementation, only alphabetical characters are shifted, and non-alphabetic characters are unchanged.
        """)

    # Encryption Section
    st.subheader("Encrypt a message")
    text = st.text_area("Enter a message")
    shift = st.number_input("Enter shift value", min_value=1, max_value=25, step=1)

    if st.button("Encrypt"):
        if text == "":
            st.warning("Please enter a message to encrypt")
        else:
            encrypted_message = caesar_encrypt(text, shift)
            st.success("Encrypted message")
            st.info(encrypted_message)

    # Decryption Section
    st.subheader("Decrypt a message")
    encrypted_message_input = st.text_area("Enter encrypted message")

    if st.button("Decrypt"):
        if encrypted_message_input == "":
            st.warning("Please enter a message to decrypt")
        else:
            decrypted_message = caesar_decrypt(encrypted_message_input, shift)
            st.success("Decrypted message")
            st.info(decrypted_message)

    # Information Section in Sidebar
    with st.expander("About us"):
        st.markdown("""
        Team 8:
            - 2210511045 - Faiz Firstian Nugroho
            - 2210511049 - Daffa Andika Firmansyah
            - 2210511061 - Rofief Amanulloh
            - 2210511076 - Othman Hanif Wiradharma
            - 2210511080 - Muhammad Reza Adi Pratama
        """
        )

page_name = {
    "Welcome Page": welcome_page,
    "RSA": rsa_page,
    "TripleDes": triple_des_page,
    "Blowfish": blowfish_page,
    "Caesar Cipher": caesar_page
}

# Display a selectbox in the sidebar with the names of the pages
page_select = st.sidebar.selectbox("Select page", list(page_name.keys()))

# Execute the selected page function
page_name[page_select]()
