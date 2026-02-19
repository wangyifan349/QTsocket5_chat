import random
from typing import List, Tuple

# Function to generate random polynomial coefficients
def generate_polynomial_coefficients(secret: int, threshold: int) -> List[int]:
    coefficients = [secret]  # secret is the constant term a0
    for _ in range(threshold - 1):  # Generate k-1 random coefficients
        coefficients.append(random.randint(1, 256))
    return coefficients

# Function to create shares
def generate_shares(secret: int, total_shares: int, threshold: int) -> List[Tuple[int, int]]:
    coefficients = generate_polynomial_coefficients(secret, threshold)
    shares = []
    for x_value in range(1, total_shares + 1):  # Generate shares by evaluating the polynomial
        y_value = sum(coefficient * (x_value ** exponent) for exponent, coefficient in enumerate(coefficients))
        shares.append((x_value, y_value))
    return shares

# Function to reconstruct the secret using Lagrange Interpolation
def reconstruct_secret(shares: List[Tuple[int, int]], threshold: int) -> int:
    def lagrange_interpolation(x_value: int, x_values: List[int], y_values: List[int]) -> int:
        def basis_polynomial(j: int) -> int:
            numerator = 1
            denominator = 1
            for m in range(len(x_values)):
                if m != j:
                    numerator *= x_value - x_values[m]
                    denominator *= x_values[j] - x_values[m]
            return numerator // denominator
        
        result = 0
        for j in range(len(y_values)):
            result += y_values[j] * basis_polynomial(j)
        return result
    
    x_values, y_values = zip(*shares)  # Extract x and y values from the shares
    return lagrange_interpolation(0, x_values, y_values)  # Reconstruct secret at x = 0

# Function to display menu and handle user choices
def display_menu():
    while True:
        print("\nShamir's Secret Sharing Menu:")
        print("1. Create and share a secret")
        print("2. Recover a secret from shares")
        print("3. Exit")
        
        user_choice = input("Please choose an option (1/2/3): ").strip()
        
        if user_choice == "1":
            create_and_share_secret()
        elif user_choice == "2":
            recover_secret_from_shares()
        elif user_choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid choice, please select again.")

# Function to create and share a secret
def create_and_share_secret():
    secret_value = int(input("Enter the secret to be shared: "))
    total_shares = int(input("Enter the total number of shares: "))
    threshold = int(input("Enter the threshold (minimum number of shares required to recover the secret): "))
    
    shares = generate_shares(secret_value, total_shares, threshold)
    print(f"\nShares created: {shares}")
    print("Please keep these shares safe!")

# Function to recover the secret
def recover_secret_from_shares():
    threshold = int(input("Enter the threshold (minimum number of shares required to recover the secret): "))
    shares = []
    print("Enter the shares one by one in the format x,y (e.g., 1,1494):")
    for _ in range(threshold):
        share_input = input(f"Enter share {_ + 1}: ")
        x_value, y_value = map(int, share_input.split(","))
        shares.append((x_value, y_value))
    
    recovered_secret = reconstruct_secret(shares, threshold)
    print(f"\nRecovered secret: {recovered_secret}")

# Main program
if __name__ == "__main__":
    display_menu()
