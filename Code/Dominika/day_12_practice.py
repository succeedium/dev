print("Task 1")
def say_hello():
    print("hello from python")
    
say_hello()
say_hello()

print("Task 2")
def greet(name):
    print(f"Hello {name}")

greet("Dominika")
greet("Monika")
greet("Vlad")

print("Task 3")
def make_lower(text):
    return text.strip().lower()

print(make_lower("TEAMONE"))
print(make_lower("CBC"))
print(make_lower("HELLO"))

print("Task 4")
def clean_email(email):
    return email.strip().lower()

print(clean_email("  Name@GMAIL.com  "))
print(clean_email(" ADMIN@Test.ca "))
print(clean_email("user@yahoo.com"))

print("Task 5")

def get_username(email):
    if "@" in email:
        at_pos = email.find("@")
        return email[:at_pos]
print(get_username("name@gmail.com"))

print("Task 6")

def get_domain(email):
    if "@" in email:
        at_pos = email.find("@")
        return email[at_pos+1:]
print(get_domain("name@gmail.com"))

print("Task 7")

def looks_valid(email):
    if "@" in email:
        return True
    else:
        return False
print(looks_valid("namegmail.com"))
print(looks_valid("bademail.com"))
print(looks_valid("admin@test.ca"))

print("Task 8")

email = "bademail.com"

if looks_valid(email):
    print(get_domain(email))
else:
    print("invalid email")

email = "admin@test.ca"

if looks_valid(email):
    print(get_domain(email))
else:
    print("invalid email")

print("Task 9")

email = "  ADMIN@Test.ca  "
clean_email2 = clean_email(email)

if looks_valid(clean_email2):
    print("valid looking")
else:
    print("invalid")
print(email)
print(clean_email2)

print("Task 10")

email = "  USER@GMAIL.com  "
clean_email3 = clean_email(email)
if looks_valid(clean_email3):
    print(get_username(clean_email3))
    print(get_domain(clean_email3))
else:
    print("invalid email")

print("Task 11")
emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca"]
for email in emails:
    clean_email4 = clean_email(email)
    
    if looks_valid(clean_email4):
        print(f"valid-looking: {clean_email4}")
    else:
        print(f"invalid: {clean_email4}")

print("task 12")

emails = ["a@gmail.com", "bademail.com", "c@test.ca", "admin@site.org"]
for email in emails:
    clean_email5 = clean_email(email)
    if looks_valid(clean_email5):
        print(get_domain(clean_email5))
    else:
        print("invalid email")

print("task 13")
'''
Task 13 — Large deal function
Write a function called is_large_deal(amount).

It should return True if the amount is greater than 10000.

Test it with:

8000
12000
25000
'''
def is_large_deal(amount):
    if amount > 10000:
        return True
    else:
        return False

print(is_large_deal(8000))
print(is_large_deal(12000))
print(is_large_deal(25000))

print("task 14")

def is_paid_client(status):
    if status == "paid":
        return True
    else:
        return False
print(is_paid_client("trial"))
print(is_paid_client("paid"))
print(is_paid_client("expired"))

print("task 15")

def format_client_name(name):
    clean_client = name.strip().upper()
    return clean_client
print(format_client_name("  cbc  "))
print(format_client_name(" DoorDash "))
print(format_client_name("smallco"))

print("task 16")

def is_gmail(email):
    clean_email6 = clean_email(email)
    if "gmail" in clean_email6:
        return True
    else:
        return False
print(is_gmail("A@GMAIL.com"))
print(is_gmail("b@yahoo.com"))
print(is_gmail(" c@gmail.com "))

print("task 17")

emails = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca", "SALES@SmallCo.com"]
for email in emails:
    clean_email7 = clean_email(email)
    if looks_valid(clean_email7):
        print(get_username(clean_email7))
        print(get_domain(clean_email7))
    else:
        print("invalid email")

print("task 18")
'''
Task 18 — Count valid emails with a function
Use:

emails = ["a@gmail.com", "bademail.com", "c@test.ca", "hello.com", "admin@site.org"]
Write or reuse:

looks_valid(email)
Create valid_count = 0.

Loop through emails.

If looks_valid(email) returns True, add 1 to the count.

Print the final count.'''

emails = ["a@gmail.com", "bademail.com", "c@test.ca", "hello.com", "admin@site.org"]
valid_count = 0
for email in emails:
    if looks_valid(email) == True:
        valid_count = valid_count + 1
print(valid_count)
    
print("task 19")

client_name = "  cbc  "
email = " ADMIN@CBC.ca "
status = "paid"

print(format_client_name(client_name))
print(clean_email(email))
print(looks_valid(email))
if status == "paid":
    print("paid client")
else:
    print("not paid client")

print("task 20")

emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca", "contact@yahoo.com"]
for email in emails:
    clean_email20 = clean_email(email)
    
    if looks_valid(clean_email20):
        print(clean_email20)
        print(get_username(clean_email20))
        print(get_domain(clean_email20))
        
        if is_gmail(clean_email20):
            print("gmail email")
    else:
       print("invalid email")