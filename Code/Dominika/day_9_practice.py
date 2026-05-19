'''Task 1 — Print all clients
Create a list of 4 client names.
Use a for loop to print each client on its own line.
'''
print("Task 1")

clients = ["domi", "moni", "kiki", "jiki"]

for client in clients:
    print(client)

'''
Task 2 — Print all emails cleaned
Create a list of messy emails, for example:
emails = ["  A@GMAIL.com  ", " B@YAHOO.com ", "c@Test.ca"]

Use a for loop to:
clean each email with .strip().lower()
print the cleaned email
'''
print("Task 2")

emails = ["  A@GMAIL.com  ", " B@YAHOO.com ", "c@Test.ca"]

for email in emails:
    print(email.strip().lower())

'''
Task 3 — Email validity check
Use:
emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

Loop through the emails.
For each email:
print the email
print "valid-looking" if it contains @
otherwise print "missing @"
'''
print("Task 3")

emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for email in emails:
    print(email)
    
    if "@" in email:
        print("valid email")
    else:
        print("missing @")

'''
Task 4 — Print @ positions
Use:
emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

Loop through the emails.
For each email:
print the email
print the position of @ using .find("@")
'''
print("Task 4")

emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for email in emails:
    print(email)
    print(email.find("@"))

'''
Task 5 — Extract domains with find()
Use:
emails = ["a@gmail.com", "b@yahoo.com", "bademail.com", "c@test.ca"]

Loop through the emails.
For each email:
if it contains @, use .find("@") and slicing to print the domain
otherwise print "invalid email"
'''
print("Task 5")

emails = ["a@gmail.com", "b@yahoo.com", "bademail.com", "c@test.ca"]

for email in emails:
    print(email)
    if "@" in email:
        at_pos = email.find("@")
        domain = email[at_pos+1:]
        print(domain)
    else:
        print("invalid email")


'''
Task 6 — Split a comma-separated domain string
Store:
domain_text = "gmail.com,yahoo.com,test.ca"

Use .split(",") to create a list called domains.
Print:
the full list
the first domain
the second domain
the third domain
'''
print("Task 6")

domain_text = "gmail.com,yahoo.com,test.ca"

domains = domain_text.split(",")
print(domains)

print(domains[0])
print(domains[1])
print(domains[2])

'''
Task 7 — Loop through domains from split
Use:
domain_text = "gmail.com,yahoo.com,test.ca"

Split it into a list.
Then use a for loop to print each domain on its own line.
'''
print("Task 7")

domain_text = "gmail.com,yahoo.com,test.ca"

domains_split = domain_text.split(",")

for domains in domains_split:
    print(domains)

'''
Task 8 — Split one email
Store:
email = "name@gmail.com"

Use .split("@") to create a list called parts.
Print:
the full parts list
the username part
the domain part
'''
print("Task 8")

email = "name@gmail.com"

parts = email.split("@")

print(parts)
print(parts[0])
print(parts[1])

'''Task 9 — Compare find() and split()
Store:
email = "name@gmail.com"

Extract username and domain in two ways.
First way:
use .find("@") and slicing
Second way:
use .split("@")
Print both results.
Answer in comments:
which version feels easier?
which version uses positions?
which version creates a list?
'''
print("Task 9")

print("first way")

email = "name@gmail.com"

at_pos = email.find("@")
username1 = email[:at_pos]
print(username1)
domain1 = email[at_pos+1:]
print(domain1)

print("second way")

split_email = email.split("@")
username2 = split_email[0]

domain2 = split_email[1]
print(username2)
print(domain2)

#which version feels easier? Split() feels easier, it's shorter to write and more cleaner.
#which version uses positions? Find() because you need positiions (indexes) to locate what you are finding.
#which version creates a list? Split() creates a list because it turns a string into multiple values.
'''
Task 10 — Loop and split emails
Use:
emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]

Loop through the list.
For each email:
split it by @
print the username
print the domain
'''

print("Task 10") 

emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]

for email in emails:
    print("email: ",email)
    split_email = email.split("@")
    print("username:",split_email[0])
    print("domain:",split_email[1])

''' Task 11 — Safe split with invalid email
Use:
emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

Loop through the list.
For each email:
if it contains @, split and print the domain
otherwise print "cannot split invalid email"
'''
print("Task 11")

emails = ["a@gmail.com", "bademail.com", "c@test.ca"]

for email in emails:
    print(email)
    if "@" in email:
        split_email = email.split("@")
        print(split_email[1])
    else:
        print("cannot split invalid email")    


'''
Task 12 — Client roll call
Use:
clients = ["CBC", "SmallCo", "News Corp"]

Loop through the clients and print:
Client: CBC
Client: SmallCo
Client: News Corp

Use an f-string.
'''
print("Task 12")

clients = ["CBC", "SmallCo", "News Corp"]

for client in clients:
    print(f"Client: {client}")

'''
Task 13 — Status messages
Use:
statuses = ["trial", "paid", "expired", "lead"]

Loop through the statuses.
For each status:
if it is "trial", print "trial account"
if it is "paid", print "paid account"
otherwise print "other status"
This can use if, elif, and else.
If elif has not been introduced yet, use only if / else or save this as an optional challenge.
'''
print("Task 13")

statuses = ["trial", "paid", "expired", "lead"]

for status in statuses:
    print(status)
    if status == "trial":
        print("trial account")

    elif status == "paid":
        print("paid account")
        
    else:
        print("other status")

'''Task 14 — Mini email report
Use:
emails = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca", "SALES@SmallCo.com"]

Loop through each email.
For each email:
clean it
print the cleaned email
if it contains @:
split it by @
print the username
print the domain
otherwise:
print "invalid email"
'''
print("Task 14")
emails = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca", "SALES@SmallCo.com"]

for email in emails:
    clean_email = email.strip().lower()
    print(clean_email)
    if "@" in clean_email:
        split_email = clean_email.split("@")
        domain = split_email[1]
        username = split_email[0]
        print(domain)
        print(username)
    else:
        print("invalid email")

''' Task 15 — Split words and loop
Store:
client_name = "Big Blue Company"

Use .split(" ") to turn it into a list of words.
Then:
print the full list
print the first word
print the second word
print the third word
use a loop to print each word on its own line
'''
print("Task 15")

client_name = "Big Blue Company"

split_client_name = client_name.split(" ")

print(split_client_name[0])
print(split_client_name[1])
print(split_client_name[2])

for word in split_client_name:
    print(word)

'''Task 16 — Mini Week 2 starter project
Use:
emails_text = "admin@cbc.ca,user@smallco.com,bademail.com,contact@newscorp.com"

Do this step by step:
Split the text into a list of emails.
Loop through the emails.
Clean each email.
If it contains @, split it into username and domain.
Print a short report for each email.
If it does not contain @, print "invalid email".
Example output idea:
Email: admin@cbc.ca
Username: admin
Domain: cbc.ca

Email: bademail.com
Invalid email'''
print("Task 16")

emails_text = "admin@cbc.ca,user@smallco.com,bademail.com,contact@newscorp.com"

split_text = emails_text.split(",")

for email in split_text:
    clean_email = email.strip().lower()
    print("email: ",clean_email)
    if "@" in clean_email:
        print("username: ",clean_email.split("@")[0])
        print("domain: ",clean_email.split("@")[1])
    else:
        print("invalid email")

        