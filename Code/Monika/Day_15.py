# Task 1 — Fix syntax errors

email = "name@gmail.com"
if "@" in email:
    print("valid")
else:
    print("invalid")

# Task 2 — Fix variable name mistakes

client_name = "CBC"
contact_email = "admin@cbc.ca"

print(client_name)
print(contact_email)

# Task 3 — Fix string and number combination

client = "SmallCo"
amount = 8000

print(f"{client} pays {amount} per year")

# Task 4 — Fix list index error

emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]

print(emails[2])
print(len(emails))
print(emails[len(emails) - 1])

# Task 5 — Add debug prints

email = "  USER@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]

print(domain)
print("DEBUG original email:", email)
print("DEBUG clean_email:", clean_email)
print("DEBUG @ position:", at_pos)
print("DEBUG domain:", domain)

# Task 6 — Fix loop indentation

emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for email in emails:
  if "@" in email:
    print(email)


# Task 7 — Debug wrong logic

email = "bademail.com"
at_pos = email.find("@")
if "@" in email:
  domain = email[at_pos + 1:]
  print(domain)
else:
   print("invalid email")

#Task 8 — Fix a function

def clean_email(email):
 return email.strip().lower()

print(clean_email("  Name@GMAIL.com  "))

# Task 9 — Explain three errors in comments

# SyntaxError means ... python spelling incorrect, it could also be incorrect placement of symbols like colons and brackets.
# NameError means ...   Name is spelled wrong or non existent
# IndexError means ...  index out of range

# Task 10 — Mini debugging challenge

emails = [" A@GMAIL.com ", "bademail.com", " C@Test.ca "]

valid_count = 0

for email in emails:
    clean_email = email.strip().lower()
    if "@" in clean_email:
        valid_count = valid_count + 1
        print(clean_email)

print("Valid emails: " + str(valid_count))