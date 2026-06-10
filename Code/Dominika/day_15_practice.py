print("task 1")
#Task 1 — Fix syntax errors
'''Copy this broken code into your file and fix it:

email = "name@gmail.com"
if "@" in email
    print("valid")
else
    print("invalid")
Expected behavior:

if the email contains @, print valid
otherwise print invalid'''

email = "name@gmail.com"
if "@" in email:
    print("valid")
else:
    print("invalid")

print("task 2")
'''Task 2 — Fix variable name mistakes
Copy this broken code and fix it:

client_name = "CBC"
contact_email = "admin@cbc.ca"

print(client)
print(contactemail)
Expected behavior:

print the client name
print the contact email'''

client_name = "CBC"
contact_email = "admin@cbc.ca"

print(client_name)
print(contact_email)

print("task 3")
'''Task 3 — Fix string and number combination
Copy this broken code and fix it using an f-string:

client = "SmallCo"
amount = 8000

print(client + " pays " + amount + " per year")
Expected output idea:

SmallCo pays 8000 per year'''

client = "SmallCo"
amount = 8000

print(f"{client} pays {amount} per year")

print("task 4")

'''Task 4 — Fix list index error
Copy this code and fix the index problem:

emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]

print(emails[3])
Then add two more print lines:

print the length of the list using len()
print the last email using len(emails) - 1
'''

emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]
print(emails[2])
print(len(emails))
print(emails[len(emails)-1])

print("task 5")
'''Task 5 — Add debug prints
Start with this code:

email = "  USER@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]

print(domain)
Add debug prints so the program prints:

original email
clean email
position of @
domain
Use clear labels like:

print("DEBUG clean_email:", clean_email)'''

email = "  USER@GMAIL.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print("DEBUG original email:", email)
print("DEBUG clean_email:", clean_email)
print("DEBUG at_pos:", at_pos)
print("DEBUG domain:", domain)

print("task 6")
'''Copy this broken code and fix it:

emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for email in emails:
if "@" in email:
print(email)
Expected behavior:

print only emails that contain @'''

emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for email in emails:
    if "@" in email:
        print(email)

print("task 7")
'''Task 7 — Debug wrong logic
This code runs, but the result is wrong or unsafe:

email = "bademail.com"
at_pos = email.find("@")
domain = email[at_pos + 1:]

print(domain)
Fix it so the code checks whether the email contains @ before extracting the domain.

Expected behavior:

if valid-looking, print the domain
otherwise print invalid email'''

email = "bademail.com"
at_pos = email.find("@")
domain = email[at_pos + 1:]
if "@" in email:
    print(domain)
else:
    print("invalid email")

print("task 8")

'''Task 8 — Fix a function
Copy this broken function and fix it:

def clean_email(email)
return email.strip().lower()

print(clean_email("  Name@GMAIL.com  "))
Expected output:

name@gmail.com
'''
def clean_email(email):
    return email.strip().lower()

print(clean_email("  Name@GMAIL.com  "))

print("task 9")
'''Task 9 — Explain three errors in comments
Write three short comments in your Python file explaining these errors:

# SyntaxError means; you made a mistake with the syntax
# NameError means; you did not define a varible
# IndexError means; you went out of range, so the index does not exist
Use your own words.'''

print("task 10")
'''Task 10 — Mini debugging challenge
Fix this program. It has several problems.

emails = [" A@GMAIL.com ", "bademail.com", " C@Test.ca "

valid_count = 0

for email in emails
    clean_email = email.strip.lower()
    if "@" in clean_email:
        valid_count = valid_count + 1
        print(clean_email)

print("Valid emails: " + valid_count)
Correct behavior:

clean each email
print only valid-looking emails
count valid-looking emails
print the final count
Hint: fix one problem at a time.'''

emails = [" A@GMAIL.com ", "bademail.com", " C@Test.ca "]

valid_count = 0

for email in emails:
    clean_email = email.strip().lower()
    if "@" in clean_email:
        valid_count = valid_count + 1
        print(clean_email)

print(f"Valid emails: {valid_count}")