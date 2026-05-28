print("""------TASK 1----------
      """)

emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
for email in emails:
    if "@" in email:
        print(email)

print("""
      
------TASK 2----------
      """)


emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
for email in emails:
    if "@" in email:
        print(f"valid-looking: {email}")
    else:
        print(f"skipped: {email}")

print("""
      
------TASK 3----------
      """)

emails = ["a@gmail.com", "b@yahoo.com", "c@gmail.com", "admin@test.ca"]
for email in emails:
    if "gmail" in email:
        print(email)


print("""
      
------TASK 4----------
      """)

emails = ["A@GMAIL.com", "b@yahoo.com", " C@Gmail.com ", "admin@test.ca"]
for email in emails:
    if "gmail" in email.strip().lower():
        print(email.strip().lower())

print("""
      
------TASK 5----------
      """)   

domains = ["gmail.com", "test.ca", "trialcompany.com", "demo.test.org"]
for domain in domains:
    if "test" in domain:
        print(domain)


print("""
      
------TASK 6----------
      """)  

clients = ["CBC", "DoorDash", "Pinterest", "Canada Test", "SmallCo"]
for client in clients:
    if "c" in client.strip().lower():
        print(client)

print("""
      
------TASK 7----------
      """) 

emails = ["a@gmail.com", "bad@gmail.com", "c@test.ca", "hello@gmail.com", "admin@site.org"]

print(f"We have {len(emails)} emails to check.")

print("""
      
------TASK 8 ----------
      """) 

email = "name@gmail.com"
emails = ["a@gmail.com", "b@yahoo.com", "bademail"]
print(len(email))
print(len(emails))

print("""
      
------TASK 9 ----------
      """) 
clients = ["CBC", "DoorDash", "Pinterest", "SmallCo"]
print(len(clients) -1)

print("""
      
------TASK 10 ----------
      """) 

emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
valid_count = 0
for email in emails:
    if "@" in email:
        valid_count = valid_count + 1
print(valid_count)

print("""
      
------TASK 11 ----------
      """) 

emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
invalid_count = 0
for email in emails:
    if "@" not in email.strip().lower():
        invalid_count = invalid_count + 1
print(invalid_count)

print("""
      
------TASK 12 ----------
      """) 

emails = ["a@gmail.com", "b@yahoo.com", "c@gmail.com", "admin@test.ca", "sales@GMAIL.com"]
gmail_count = 0
for email in emails:
    if "gmail" in email.strip().lower():
        gmail_count = gmail_count + 1
print(gmail_count)

print("""
      
------TASK 13 ----------
      """) 

emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
for email in emails:
    if "@" in email.strip().lower():
        print(email[email.find("@") + 1:])
    else: 
        print("invalid")

print("""
      
------TASK 14 ----------
      """) 
count = 0
while count < 5:
    print(count)
    count = count + 1

print("""
      
------TASK 15 ----------
      """)

emails = ["a@gmail.com", "b@yahoo.com", "bademail"]
index = 0
while index < len(emails):
    print(emails[index])
    index = index + 1

print("""
      
------TASK 16 ----------
      """)


emails = ["a@gmail.com", "b@yahoo.com", "bademail"]
index = 0
while index < len(emails):
    print(emails[index])
    if "@" in emails[index]:
        print( "valid-looking")
    else:
        print("missing @")
    index = index + 1

print("""
      
------TASK 17 ----------
      """)

emails = ["bademail", "hello.com", "admin@site.org", "user@test.ca"]
index = 0
found = False
while found == False:
    if "@" in emails[index]:
        print(emails[index])
        found = True
    else:
        index = index + 1

print("""
      
------TASK 18 ----------
      """)

emails = [" A@GMAIL.com ", "bademail", "c@test.ca", "hello.com", "sales@gmail.com"]
email_count = 0
valid_count = 0
gmail_count = 0

for email in emails:
  if email_count < len(emails):
    
    clean_email = email.strip().lower()
    if "@" in clean_email:
        print("Valid looking")
        valid_count = valid_count + 1
        email_count = email_count + 1
        
    else: 
        print("Invalid looking")
        email_count = email_count + 1
    if "gmail" in clean_email:
        gmail_count = gmail_count + 1

print(email_count)
print(valid_count)
print(gmail_count)













