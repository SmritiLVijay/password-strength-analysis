from password_strength_analysis import evaluate_password_strength, hash_password_sha256, hash_password_bcrypt, test_password


def print_menu():
    print("----- Password Strength Analysis & Hashing -----")
    print("1. Evaluate Password Strength")
    print("2. Hash Password using SHA-256")
    print("3. Hash Password using bcrypt")
    print("4. Exit")


def get_menu_choice():
    choice = input("Enter your choice (1-4): ")
    return choice


def evaluate_password_strength_interface():
    password = input("Enter a password: ")
    if not test_password(password):
        print("Password does not meet all requirements.")
    else:
        password_strength = evaluate_password_strength(password)
        print("Password Strength:", password_strength)


def hash_password_sha256_interface():
    password = input("Enter a password: ")
    hashed_password = hash_password_sha256(password)
    print("SHA-256 Hashed Password:", hashed_password)


def hash_password_bcrypt_interface():
    password = input("Enter a password: ")
    hashed_password = hash_password_bcrypt(password)
    print("bcrypt Hashed Password:", hashed_password)


def main():
    while True:
        print_menu()
        choice = get_menu_choice()

        if choice == '1':
            evaluate_password_strength_interface()
        elif choice == '2':
            hash_password_sha256_interface()
        elif choice == '3':
            hash_password_bcrypt_interface()
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()