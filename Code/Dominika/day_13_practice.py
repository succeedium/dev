print("task 1")
#create a email varible
email = "  Name@GMAIL.com  "
#Clean the email, remove spaces and change the email to lowercase. 
clean_email = email.strip().lower()
#print it
print(clean_email)

print("task 2")
x = "  ADMIN@CBC.ca  "
y = x.strip().lower()
z = y.find("@")
a = y[z + 1:]
print(a)
# better variable names:
email = "  ADMIN@CBC.ca  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)

print("task 3")
email = "  User@Test.ca  "
print(email.strip().lower()[email.strip().lower().find("@") + 1:])

clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)

print("task 4")

#cleans email.
email = "  Name@GMAIL.com  "
clean_email = email.strip().lower()

#if "@" in email, print username and domain.
if "@" in clean_email:
    at_pos = clean_email.find("@")
    username = clean_email[:at_pos]
    domain = clean_email[at_pos+1:]
    print(username)
    print(domain)
#otherwise prints invalid if no "@" in email
else:
    print("invalid email")

print("task 5")

email = "  Sales@SmallCo.com  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
username = clean_email[:at_pos]
domain = clean_email[at_pos + 1:]

print("DEBUG clean_email:", clean_email)
print("DEBUG at_pos:", at_pos )
print("DEBUG username", username )
print("DEBUG domain", domain )

print("task 6")

'''Improve this code so it is readable:

e="  USER@Test.ca  "
c=e.strip().lower()
if "@" in c:
 p=c.find("@")
 print(c[p+1:])
else:
 print("bad")
Your improved version should include:

better variable names
proper indentation
helper variables
clearer output message
at least two useful comments'''
email ="  USER@Test.ca  "
#cleans email
clean_email = email.strip().lower()
# if "@" in the clean email, find the pos, and the splice to get the domain.
if "@" in clean_email:
   at_pos = clean_email.find("@")
   domain = clean_email[at_pos+1:]
   print(domain)
else:
    print("invalid email")

print("task 7")

def clean_email(email):
    return email.strip().lower()

def looks_valid(email):
    if "@" in email:
        return True
    else:
        return False
def get_domain(email):
    if "@" in email:
        cleaned_email = clean_email(email)
        at_pos = cleaned_email.find("@")
        domain = cleaned_email[at_pos+1:]
        return domain
    
email = "  Admin@CBC.ca  "
print(clean_email(email))
print(looks_valid(email))
print(get_domain(email))

print("task 8")

emails = ["  ADMIN@CBC.ca  ", "bademail.com", " User@Test.ca "]

#loops though emails
for email in emails:

    #cleans each email
    clean_email = email.strip().lower()

    # if vaild - finds at pos, prints username & domain
    if "@" in clean_email:
        at_pos = clean_email.find("@")
        username = clean_email[:at_pos]
        domain = clean_email[at_pos+1:]
        print("username:", username)
        print("domain:", domain)

    #otherwise prints "invalid email"
    else:
        print("invalid email")

print("task 9")

#list stores emails, with @ and without.
emails = ["a@gmail.com", "bademail.com", "c@test.ca"]
valid_count = 0
#loops through emails
for email in emails:
    #checks if @ in email, if so adds +1 to valid_count
    if "@" in email:
        valid_count = valid_count + 1
#prints total valid_count
print(valid_count)

print("task 10")

#Version A
x = "  ADMIN@CBC.ca  "
y = x.strip().lower()
z = y.find("@")
a = y[z + 1:]
print(a)

#Version B
email = "  ADMIN@CBC.ca  "
clean_email = email.strip().lower()
at_pos = clean_email.find("@")
domain = clean_email[at_pos + 1:]
print(domain)
#Version B is better because its much easier to understand and read.