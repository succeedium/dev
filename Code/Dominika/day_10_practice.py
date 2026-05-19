'''Task 1 — Valid email printer
Use:
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
Print only the emails that contain @.'''
print("Task 1")
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
for email in emails:
    if "@" in email:
        print(email)

'''Task 2 — Show valid and skipped emails
Use the same list.
For each email:
print "valid-looking: EMAIL" if it contains @
print "skipped: EMAIL" otherwise
'''
print("Task 2")
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
for email in emails:
    if "@" in email:
        print(f"valid-looking: {email}")
    else:
        print(f"skipped: {email}")

'''
Task 3 — Gmail finder
Use:
emails = ["a@gmail.com", "b@yahoo.com", "c@gmail.com", "admin@test.ca"]
Print only the emails that contain "gmail".
'''
print("Task 3")
emails = ["a@gmail.com", "b@yahoo.com", "c@gmail.com", "admin@test.ca"]
for email in emails:
    if "gmail" in email:
        print(email)
'''
Task 4 — Gmail finder with messy capitalization
Use:
emails = ["A@GMAIL.com", "b@yahoo.com", " C@Gmail.com ", "admin@test.ca"]
For each email:
clean it with .strip().lower()
print only the Gmail emails
'''
print("task 4")
emails = ["A@GMAIL.com", "b@yahoo.com", " C@Gmail.com ", "admin@test.ca"]
for email in emails:
    clean_email = email.strip().lower()
    if "gmail" in clean_email:
        print(clean_email)
'''
Task 5 — Trial domain checker
Use:
domains = ["gmail.com", "test.ca", "trialcompany.com", "demo.test.org"]
Print only the domains that contain "test".
'''
print("Task 5")
domains = ["gmail.com", "test.ca", "trialcompany.com", "demo.test.org"]
for domain in domains:
    if "test" in domain:
        print(domain)

'''Task 6 — Client name filter
Use:
clients = ["CBC", "DoorDash", "Pinterest", "Canada Test", "SmallCo"]
Print only clients whose lowercase name contains "c".
'''
print("Task 6")
clients = ["CBC", "DoorDash", "Pinterest", "Canada Test", "SmallCo"]
for client in clients:
    if "c" in client.lower():
        print(client)

'''
Task 7 — Print list length
Create a list of 5 emails.
Print:
We have 5 emails to check.
But do not hardcode 5. Use len().
'''
print("Task 7")

emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca", "d@test.ca", "e@test.ca"]
print(f"we have {len(emails)} emails to check")

'''
Task 8 — Compare string length and list length
Use:
email = "name@gmail.com"
emails = ["a@gmail.com", "b@yahoo.com", "bademail"]
Print:
the number of characters in email
the number of items in emails
'''
print("Task 8")

email = "name@gmail.com"
emails = ["a@gmail.com", "b@yahoo.com", "bademail"]

print(len(email))
print(len(emails))
'''
Task 9 — Last item using len()
Use:
clients = ["CBC", "DoorDash", "Pinterest", "SmallCo"]
Print the last item using len().
Hint:
last index is len(clients) - 1
'''
print("Task 9")
clients = ["CBC", "DoorDash", "Pinterest", "SmallCo"]
print(clients[len(clients)-1])

'''Task 10 — Count valid-looking emails
Use:
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
Create valid_count = 0.
Loop through emails.
Each time an email contains @, add 1.
Print the final valid count.'''
print("Task 10")
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
valid_count = 0
for email in emails:
    if "@" in email:
        valid_count = valid_count + 1
print(valid_count)

'''
Task 11 — Count invalid emails
Use the same list.
Create invalid_count = 0.
Loop through emails.
Each time an email does not contain @, add 1.
Print the final invalid count.
'''
print("Task 11")
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
invalid_count = 0
for email in emails:
    if "@" not in email:
        invalid_count = invalid_count + 1
print(invalid_count)
'''
Task 12 — Count Gmail emails
Use:
emails = ["a@gmail.com", "b@yahoo.com", "c@gmail.com", "admin@test.ca", "sales@GMAIL.com"]
Loop through the emails.
Clean each email with .strip().lower().
Count how many contain "gmail".
Print the final count.
'''
print("Task 12")
emails = ["a@gmail.com", "b@yahoo.com", "c@gmail.com", "admin@test.ca", "sales@GMAIL.com"]
gmail_count = 0
for email in emails:
    clean_email = email.strip().lower()
    if "gmail" in clean_email:
        gmail_count = gmail_count + 1
print(gmail_count)
'''
Task 13 — Extract domains only from valid emails
Use:
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
Loop through emails.
For each email:
if it contains @, extract the domain using .split("@")
print the domain
otherwise skip it or print "invalid"
'''
print("Task 13")
emails = ["a@gmail.com", "bademail", "c@test.ca", "hello.com", "admin@site.org"]
for email in emails:
    if "@" in email:
        domain = email.split("@")
        print(domain[1])
    else:
        print("invalid")

'''
Task 14 — First simple while counter
Write a while loop that prints:
0
1
2
3
4
Use:
count = 0
while count < 5:
Do not forget to increase count.
'''
print("Task 14")
count = 0
while count < 5:
    print(count)
    count = count + 1
    
'''
Task 15 — while loop through emails by index
Use:
emails = ["a@gmail.com", "b@yahoo.com", "bademail"]
Use a while loop and an index variable to print each email.
Use:
while index < len(emails):
'''
print("Task 15")
emails = ["a@gmail.com", "b@yahoo.com", "bademail"]
index = 0
while index < len(emails):
    print(emails[index])
    index = index + 1


'''
Task 16 — while loop with email checks
Use:
emails = ["a@gmail.com", "bademail", "c@test.ca"]
Use a while loop.
For each email:
print the email
print "valid-looking" if it contains @
otherwise print "missing @"
Do not forget to increase the index.
'''
print("Task 16")
emails = ["a@gmail.com", "bademail", "c@test.ca"]
count = 0
while count < len(emails):
    email = emails[count]
    print(email)
    if "@" in email:
        print("valid-looking")
    else:
        print("missing @")
    count = count + 1
'''
Task 17 — Stop when a match is found
Use:
emails = ["bademail", "hello.com", "admin@site.org", "user@test.ca"]
Use a while loop to search for the first email that contains @.
When you find it:
print it
stop the loop by setting a variable like found = True
Keep this task as a challenge if needed.
'''
print("Task 17")
emails = ["bademail", "hello.com", "admin@site.org", "user@test.ca"]
index = 0
found = False

while index < len(emails) and found == False:
    email = emails[index]
    if "@" in email:
        print(email)
        found = True
    index = index + 1

'''
Task 18 — Mini filtering report
Use:
emails = [" A@GMAIL.com ", "bademail", "c@test.ca", "hello.com", "sales@gmail.com"]
Loop through the emails with a for loop.
For each email:
clean it
print whether it is valid-looking or invalid
count valid-looking emails
count Gmail emails
At the end, print:
total number of emails using len()
valid-looking count
Gmail count
'''
print("Task 18")
emails = [" A@GMAIL.com ", "bademail", "c@test.ca", "hello.com", "sales@gmail.com"]
valid_count = 0
gmail_count = 0
for email in emails:
    clean_email = email.strip().lower()
    print(clean_email)
    if "@" in clean_email:
        print("Valid looking")
        valid_count = valid_count + 1
    else:
        print("Invalid email")
    
    if "gmail" in clean_email:
        gmail_count = gmail_count + 1

print(len(emails))
print(valid_count)
print(gmail_count)

