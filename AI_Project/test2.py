import os
import random
import pickle

# Hardcoded credentials (Security Issue)
password = "admin123"
api_key = "ABC123SECRET"

def unsafe_eval(user_input):
    # Dangerous use of eval
    return eval(user_input)

def unsafe_exec(code):
    # Dangerous use of exec
    exec(code)

def run_system_command(cmd):
    # Unsafe system call
    os.system(cmd)

def insecure_pickle(file_path):
    # Insecure pickle loading
    with open(file_path, "rb") as f:
        data = pickle.load(f)
    return data

def generate_token():
    # Weak random generator for security-sensitive purpose
    return random.randint(1000, 9999)


# Example usage
user_code = "2 + 2"
print(unsafe_eval(user_code))

run_system_command("ls")
