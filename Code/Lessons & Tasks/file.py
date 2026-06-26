from pathlib import Path

script_dir = Path(__file__).resolve().parent

file_path = "Code/Dominika/emails.txt"

with open("Code/Lessons & Tasks/emails.txt", "w") as file:
    file.write("email1@trialdomain.com\n")
    file.write("email3@trialdomain.com\n")

with open("Code/Lessons & Tasks/emails.txt", "r") as file:
    print( len(file.readlines()) )

'''
# Dominika
with open(file_path, "w") as file:
    file.write("email1@trialdomain.com\n")
    file.write("email3@trialdomain.com\n")

# Monika
with open("Code/Monika/emails.txt", "w") as file:
    file.write("email1@trialdomain.com\n")
    file.write("email3@trialdomain.com\n")
'''