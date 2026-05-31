print("""------- TASK ONE -------
       """)
def say_hello(name):
    print(f"Hello! from {name}.")
say_hello("python")
say_hello("python")

print("""------- TASK TWO -------
       """)

def greet(name):
    print(f"Hello {name}.")
greet("Dominika")
greet("Monika")
greet("Didenko")

print("""------- TASK THREE -------
       """)

def make_lower(text):
    print(text.lower())

make_lower("TEAMONE")
make_lower("CBC")
make_lower("HELLO")

print("""------- TASK FOUR -------
       """)
def clean_email(email):
    clean = email.lower().strip()
    return clean
print(clean_email("  Name@GMAIL.com  "))
print(clean_email(" ADMIN@Test.ca "))
print(clean_email("user@yahoo.com"))

print("""------- TASK FIVE -------
       """)

def get_username(email):
    at_pos = email.find("@")
    return email[:at_pos]

print(get_username("name@gmail.com"))

print("""------- TASK SIX -------
       """)

def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos+1:]
print(get_domain("name@gmail.com"))

print("""------- TASK SEVEN -------
       """)
def looks_valid(email):
    if "@" in email:
        return True
    else:
        return False
    
print(looks_valid("name@gmail.com"))
print(looks_valid("bademail.com"))
print(looks_valid("admin@test.ca"))

print("""------- TASK EIGHT -------
       """)

def looks_valid(email):
    if "@" in email:
        return True
    else:
        return False
    
def get_domain(email):
    at_pos = email.find("@")
    return email[at_pos+1:]

email = "bademail.com"

if looks_valid(email) == True:
    print(get_domain(email))

email =  "admin@test.ca"

if looks_valid(email) == True:
    print(get_domain(email))

print("""------- TASK NINE -------
       """)

email = "  ADMIN@Test.ca  "
print(email)
print(clean_email(email))
print(looks_valid(email))

print("""------- TASK TEN -------
       """)

email = "  USER@GMAIL.com  "

clean_email(email)
if looks_valid(email) == True:
    print(get_username(email.strip().lower()))
    print(get_domain(email.strip().lower()))
else: print("invalid email")

print("""------- TASK ELEVEN -------
       """)

emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca"]

for email in emails:
    clean = clean_email(email)
    looks_valid(clean)
    if looks_valid(clean) == True:
        print(f"valid-looking: {clean}")
    else: print(f"invalid: {clean}")

print("""------- TASK TWELVE -------
       """)
    
emails = ["a@gmail.com", "bademail.com", "c@test.ca", "admin@site.org"]
for email in emails:
    if looks_valid(email) == True:
       print(get_domain(email))
    else:
        print("invalid email.")

print("""------- TASK THIRTEEN -------
       """)

def is_large_deal(amount):
    if amount > 10000:
        return True
    else: return False

print(is_large_deal(8000))
print(is_large_deal(12000))
print(is_large_deal(25000))

print("""------- TASK FOURTEEN -------
       """)

def is_paid_client(status):
    if status.lower() == "paid":
        return True
    
print(is_paid_client("trial"))
print(is_paid_client("paid"))
print(is_paid_client("expired"))

print("""------- TASK FIFTEEN -------
       """)

def format_client_name(name):
    clean = name.strip().upper()
    return clean
print(format_client_name(" cbc "))
print(format_client_name( "DoorDash" ))
print(format_client_name("smallco"))

print("""------- TASK SIXTEEN -------
       """)

def is_gmail(email):
    clean = email.strip().lower()
    if "gmail" in clean:
        return True
    else:
        return False
    
print(is_gmail("A@GMAIL.com"))
print(is_gmail("b@yahoo.com"))
print(is_gmail(" c@gmail.com "))

print("""------- TASK SEVENTEEN -------
       """)

emails = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca", "SALES@SmallCo.com"]
for email in emails:
    clean = email.strip().lower()
    if looks_valid(clean) == True:
        print(get_username(clean))
        print(get_domain(clean))
    else: 
        print("invalid email")

print("""------- TASK EIGHTEEN -------
       """)

emails = ["a@gmail.com", "bademail.com", "c@test.ca", "hello.com", "admin@site.org"]

valid_count = 0
for email in emails:
    if looks_valid(email) == True:
        valid_count = valid_count + 1
    print(valid_count)

print("""------- TASK NINETEEN -------
       """)

client_name = "  cbc  "
email = " ADMIN@CBC.ca "
status = "paid"

print(format_client_name(client_name))
print(clean_email(email))
print(looks_valid(clean_email(email)))
 
if status.strip().lower() == "paid":
    print("Client has paid.")
else: print("Cliet has not paid yet.")

print("""------- TASK TWENTY -------
       """)

emails = ["  A@GMAIL.com  ", "bademail.com", "user@test.ca", "contact@yahoo.com"]

for email in emails:
    clean = email.strip().lower()
    if looks_valid(email) == True:
        print(clean)
        print(get_username(clean))
        print(get_domain(clean))
        print(is_gmail(clean))
    else: 
        print("Invalid")
        