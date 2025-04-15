from passlib.context import CryptContext

# Initialize the CryptContext with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to hash the password
def hash_password(password: str):
    return pwd_context.hash(password)

# Function to verify the password
def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# Example: Manually creating a hashed password
plain_password  = "myTestAdmin2025"
hashed_password = hash_password(plain_password)

print(f"Plain password: {plain_password}")
print(f"Hashed password: {hashed_password}")

# Verifying the password
is_verified = verify_password(plain_password, hashed_password)
print(f"Password verified: {is_verified}")
