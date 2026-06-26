from pathlib import Path

script_dir = Path(__file__).resolve().parent

with open(script_dir / "emails.txt", "w") as file:
    file.write("email1@trialdomain.com\n")
    file.write("email2@trialdomain.com\n")
    file.write("email3@trialdomain.com\n")


with open(script_dir / "emails.txt", "a") as file:
    file.write("email4@trialdomain.com\n")

with open(script_dir / "emails.txt", "w") as file:
    file.write("email5@trialdomain.com\n")


with open(script_dir / "emails.txt", "r") as file:
    text = file.read()
    
print(text)