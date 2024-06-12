import os


# Vulnerability: Command Injection
def command_injection(user_input):
    os.system(user_input)


if __name__ == "__main__":
    user_input = input("Enter a command: ")
    command_injection(user_input)
