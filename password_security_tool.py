# simple password tool

import re
import hashlib
import bcrypt
import subprocess
import time


# strength check
def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Use 12+ characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add a number.")

    # FIXED REGEX ↓↓↓↓↓
    if re.search(r"[!@#$%^&*()_+\-\[\]{};:<>?/|]", password):
        score += 1
    else:
        feedback.append("Add special character.")

    return score, feedback



# weak hash
def sha1_hash(password):
    return hashlib.sha1(password.encode()).hexdigest()


# strong hash
def bcrypt_hash(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()


# export SHA1
def export_sha1_hash(hash_value):
    with open("sha1_for_cracking.txt", "w") as f:
        f.write(f"user1:{hash_value}\n")
    return "sha1_for_cracking.txt"


# export bcrypt
def export_bcrypt_hash(hash_value):
    with open("bcrypt_for_cracking.txt", "w") as f:
        f.write(hash_value + "\n")
    return "bcrypt_for_cracking.txt"


# show crack results
def run_john_show():
    try:
        output = subprocess.check_output(
            ["john", "--show", "--format=Raw-SHA1", "sha1_for_cracking.txt"],
            stderr=subprocess.STDOUT
        )
        return output.decode()
    except Exception as e:
        return f"Error running john: {e}"


# simulate bcrypt crack
def simulate_bcrypt_attempt():
    time.sleep(1)
    return (
        "This is only a simulation.\n"
        "Real bcrypt cracking could take YEARS.\n"
        "bcrypt is secure because it is slow."
    )
