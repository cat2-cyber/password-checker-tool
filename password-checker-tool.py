import re
import hashlib
import requests
import csv

# Function to check if a password is compromised using Pwned Passwords API
def check_pwned_password(password):
    # Step 1: Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Step 2: Get the first 5 characters of the hash
    first5 = sha1_hash[:5]
    
    # Step 3: Get the remaining part of the hash
    remaining = sha1_hash[5:]
    
    # Step 4: Query the Pwned Passwords API
    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)
    
    if response.status_code == 200:
        # Step 5: Check if the password's remaining part is in the response
        hashes = response.text.splitlines()
        for hash in hashes:
            if hash.startswith(remaining):
                return True  # Password is found in breach
        return False  # Password is not found in breach
    else:
        print("Error querying Pwned Passwords API")
        return False

# Function to check password strength (length, complexity)
def check_password_strength(password):
    # Password Strength: length, complexity checks
    if len(password) < 12:
        return False, "Password too short"
    if not re.search(r'[A-Z]', password):  # Uppercase check
        return False, "No uppercase letter"
    if not re.search(r'[0-9]', password):  # Number check
        return False, "No number"
    if not re.search(r'[@$!%*?&]', password):  # Special char check
        return False, "No special character"
    if re.match(r"^[a-zA-Z0-9]*$", password):  # Check for alphanumeric only
        return False, "Only alphanumeric characters"
    
    return True, "Strong password"

# Function to process passwords from file and check strength and pwned status
def process_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        passwords = file.readlines()

    results = {}
    for password in passwords:
        password = password.strip()  # Clean the password
        
        # Check password strength
        is_strong, message = check_password_strength(password)
        
        # Check if the password has been pwned
        is_pwned = check_pwned_password(password)

        # Store the results (strength and pwned status)
        results[password] = {
            "is_strong": is_strong,
            "message": message,
            "is_pwned": is_pwned,
            "pwned_message": "Password found in breach" if is_pwned else "Password not found in breach"
        }
    
    return results

# Export results to CSV file
def export_to_csv(results, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Password", "Strength", "Message", "Pwned", "Pwned Message"])
        for password, result in results.items():
            writer.writerow([password, 'Strong' if result['is_strong'] else 'Weak', result['message'],
                             'Yes' if result['is_pwned'] else 'No', result['pwned_message']])

# Main function to handle file input and output
def main():
    # Prompt user for input file and output file paths
    file_path = input("Enter the path to the password file: ").strip()
    output_file = input("Enter the path for the output CSV file: ").strip()
    
    results = process_file(file_path)
    
    # Print the results
    for password, result in results.items():
        print(f"Password: {password} -> {'Strong' if result['is_strong'] else 'Weak'}: {result['message']}")
        print(f"Pwned Status: {'Yes' if result['is_pwned'] else 'No'} - {result['pwned_message']}")
    
    # Export results to a CSV file
    export_to_csv(results, output_file)
    print(f"Results exported to {output_file}")

if __name__ == "__main__":
    main()
