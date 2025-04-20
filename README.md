# Secure Data Encryption System (Streamlit)

## Overview

This Streamlit-based application provides a secure way to store and retrieve text data using user-defined passkeys. The system encrypts data upon storage and requires the correct passkey for decryption. It incorporates a basic user authentication system with a lockout mechanism to enhance security. Data is stored in a JSON file for persistence.

## Features

* **User Registration:** Allows new users to create an account with a username and password.
* **Secure Login:** Implements a login system with tracking of failed attempts and a temporary lockout after three unsuccessful tries.
* **Secure Data Storage:** Enables logged-in users to encrypt and store text data associated with their account using a passkey (the user's login password).
* **Data Retrieval:** Allows logged-in users to view their stored encrypted data and attempt decryption by providing the correct passkey.
* **In-Memory Operation with Persistence:** Data is primarily managed in memory but is saved to a `secure_data.json` file for persistence across sessions.
* **`Fernet` Encryption:** Utilizes the `Fernet` library for symmetric encryption, ensuring data confidentiality.
* **Password Hashing:** Employs `PBKDF2-HMAC-SHA256` for securely hashing user passwords.
* **Lockout Mechanism:** Temporarily locks out users after three consecutive failed login attempts to prevent brute-force attacks.
* **User-Friendly Streamlit Interface:** Provides an intuitive web interface for all functionalities.

## Getting Started

1.  **Prerequisites:** Ensure you have Python installed on your system.
2.  **Installation:** Install the necessary Python libraries:
    ```bash
    pip install streamlit cryptography
    ```
3.  **Running the Application:** Navigate to the directory containing the `your_script_name.py` file (replace with the actual name of your Python script) in your terminal and run:
    ```bash
    streamlit run your_script_name.py
    ```
4.  **Access:** The application will open in your web browser.

## Usage

1.  **Registration:** New users should first register an account by navigating to the "Register" page and providing a username and password.
2.  **Login:** Existing users can log in using their registered username and password on the "Login" page. Be aware of the lockout mechanism after multiple failed attempts.
3.  **Store Data:** Once logged in, navigate to the "Store Data" page, enter the text you want to secure, and provide your login password as the passkey. Click "Encrypt And Save" to store the encrypted data.
4.  **Retrieve Data:** On the "Retrieve Data" page, you will see a list of your stored encrypted data. To decrypt a specific entry, paste the encrypted text into the provided area, enter your login password as the passkey, and click "Decrypt".

## Important Notes

* **Security Disclaimer:** This application is a demonstration of secure data handling concepts. It is **not intended for production use** without thorough security auditing and enhancements.
* **Passkey Management:** The security of your data relies entirely on the strength and secrecy of your login password, which acts as the encryption passkey.
* **In-Memory Nature:** While data is saved to a file, the application's primary operation is in memory. For more robust and scalable solutions, consider using a dedicated database.

## Author

Muhammad Muaaz Ansari
