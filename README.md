# Password Hashing and Cracking Demo

This project was made for a cybersecurity class to show how password strength, hashing, and cracking work. The user enters a password, and the program checks its strength, hashes it using SHA-1 and bcrypt, and allows SHA-1 to be cracked with John the Ripper.

For the cracking demo, a 1-million-entry wordlist was used. This list came from a GitHub user who uploaded an extended version of the rockyou dataset. It helps show how fast weak hashes like SHA-1 can be cracked if the password is common.

## How to Run

pip install bcrypt
python3 password_ui.py

## How to Crack the SHA-1 Hash

john --format=Raw-SHA1 --wordlist=wordlist_demo.txt sha1_for_cracking.txt
john --show sha1_for_cracking.txt

This demonstrates why SHA-1 is unsafe and why bcrypt is much better for storing passwords.


