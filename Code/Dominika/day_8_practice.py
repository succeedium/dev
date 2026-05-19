'''Task 1 — Email list
Create a list of five emails.
Print:
the whole list
the first email
the second email
the last email
'''

print("Task 1")

emails = ["domi@gmail.com", "dom@yahoo.com", "do@google.com", "riiiii@gmail.com", "didenko@yahoo.com"]

print(emails)
print(emails[0])
print(emails[1])
print(emails[-1])

'''Task 2 — Client list
Create a list of four client names.
Print:
the whole list
the first client
the middle two clients using a slice
the last two clients using a slice
'''
print("Task 2")

client_names = ["dom", "kimmi", "jhon", "nessa"]

print(client_names)
print(client_names[0])
print(client_names[1:3])
print(client_names[2:4])

'''Task 3 — Trial domains
Create a list of three trial domains.
Print:
the second domain
the first two domains
everything after the first domain
'''

print("Task 3")

trial_domains = ["trial domain 1", "trial domain 2", "trial_domain 3"]

print(trial_domains[1])
print(trial_domains[0:2])
print(trial_domains[1:])

'''Task 4 — Clean one email from a list
Create this list:
emails = ["  USER@GMAIL.com  ", "admin@test.ca", "contact@yahoo.com"]

Select the first email.
Create a cleaned version using .strip().lower().
Print:
the original selected email
the cleaned selected email
'''

print("Task 4")

emails = ["  USER@GMAIL.com  ", "admin@test.ca", "contact@yahoo.com"]

print(emails[0])
clean_email = emails[0].strip().lower()
print(clean_email)

'''
Task 5 — Extract domain from selected email
Use this list:
emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]

Select the second email.
Then:
find the position of @
extract the domain
print the selected email
print the domain
Expected domain:
yahoo.com
'''
print("Task 5")

emails = ["a@gmail.com", "b@yahoo.com", "c@test.ca"]

second_email = emails[1]

at_pos = second_email.find("@")

domain = second_email[at_pos+1:]

print(second_email)
print(domain)

'''Task 6 — Check selected email
Use this list:
emails = ["good@gmail.com", "bademail.com", "test@test.ca"]

Select the second email.
Use if / else to print:
"valid-looking email" if it contains @
"missing @" otherwise
Then change the selected email to the third one and run again.
'''
print("Task 6")

emails = ["good@gmail.com", "bademail.com", "test@test.ca"]

second_email = emails[1]
third_email = emails[2]

if "@" in third_email:
    print("email contains @")

else:
    print("missing @")

'''Task 7 — First and last selected characters
Use this list:
client_names = ["CBC", "DoorDash", "Pinterest"]

Select the second client.
Print:
the selected client
its first character
its first 4 characters
This combines list indexing with string indexing.
'''
print("Task 7")

client_names = ["CBC", "DoorDash", "Pinterest"]

second_email = client_names[1]

print(second_email)
print(second_email[0])
print(second_email[0:4])

'''Task 8 — Clean selected client name
Use this list:
clients = ["  cBc  ", "  DoorDASH  ", "Pinterest"]

Select the first client.
Create:
clean_client using .strip().lower()
upper_client using .strip().upper()
Print all three:
original selected client
cleaned lowercase client
cleaned uppercase client
'''

print("Task 8")

clients = ["  cBc  ", "  DoorDASH  ", "Pinterest"]

first_client = clients[0]

clean_client = first_client.strip().lower()
upper_client = clean_client.upper()

print(first_client)
print(clean_client)
print(upper_client)

'''Task 9 — Status checker
Create this list:
statuses = ["trial", "paid", "expired"]

Select one status.
Use if / else to print:
"trial account" if the selected status is "trial"
"not trial" otherwise
Then test it with each item in the list by changing the index.
'''
print("Task 9")

statuses = ["trial", "paid", "expired"]

status = statuses[0]

if status == "trial":
    print("trial account")

else:
    print("not trial")

'''
Task 10 — Parallel beginner lists
Create three lists:
clients = ["CBC", "SmallCo", "News Corp"]
emails = ["admin@cbc.ca", "user@smallco.com", "contact@newscorp.com"]
statuses = ["paid", "trial", "lead"]

Select index 1.
Print a summary sentence using the client, email, and status at index 1.
Example:
SmallCo uses user@smallco.com and has status trial.

Then change the index to 0 and run again.'''

print("Task 10")

clients = ["CBC", "SmallCo", "News Corp"]
emails = ["admin@cbc.ca", "user@smallco.com", "contact@newscorp.com"]
statuses = ["paid", "trial", "lead"]

'''
client_index_1 = clients[1]
email_index_1 = emails[1]
status_index_1 = statuses[1]

print(f"{client_index_1} uses {email_index_1} and has status {status_index_1}")
'''
selected_index = 2
print(f"{clients[selected_index]} uses {emails[selected_index]} and has status {statuses[selected_index]}")

'''Task 11 — Selected email inspector
Use this list:
emails = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca"]

Select one email by index.
Clean it.
If it contains @:
find the @
extract username
extract domain
print a clean summary
Otherwise:
print "invalid email"
Test the task with index 0, index 1, and index 2.
'''
print("Task 11")

emails = ["  ADMIN@CBC.ca  ", "bademail.com", "user@test.ca"]

email = emails[2]

clean_email = email.strip().lower()

if "@" in clean_email:
    at_pos = clean_email.find("@")
    username = clean_email[:at_pos]
    domain = clean_email[at_pos+1:]

    print(f"Username: {username}, Domain: {domain}")

else:
    print("email invalid")

'''Task 12 — Compare string slice and list slice
Use:
email = "name@gmail.com"
emails = ["name@gmail.com", "admin@test.ca", "user@yahoo.com"]

Print:
email[0:4]
emails[0:2]
Then answer in comments:
what type of thing did the first print return?
what type of thing did the second print return?
'''
print("Task 12")

email = "name@gmail.com"
emails = ["name@gmail.com", "admin@test.ca", "user@yahoo.com"]

print(email[0:4])
print(emails[0:2])

# for email, it returned 'name' because we are slicing just a string.
#for emails, it returns both values because it is a list and you need to be specific.

'''
Task 13 — Choose a domain from a list and check it
Use:
domains = ["gmail.com", "yahoo.com", "test.ca"]

Select one domain.
Use if / else to print:
"Google email" if the domain is "gmail.com"
"Other email" otherwise
Then test with different indexes.'''

print("Task 13")

domains = ["gmail.com", "yahoo.com", "test.ca"]

domain = domains[2]

if domain == "Google email":
    print("gmail.com")  
else:
    print("Other email")
'''
Task 14 — Mini account card
Use these lists:
clients = ["CBC", "SmallCo", "News Corp"]
emails = ["  ADMIN@CBC.ca  ", "user@smallco.com", "contact@newscorp.com"]
statuses = ["paid", "trial", "lead"]

Choose an index.
Create:
client
email
status
clean_email
If the cleaned email contains @:
extract username
extract domain
Print a small account card:
Client: SmallCo
Email: user@smallco.com
Username: user
Domain: smallco.com
Status: trial'''

print("Task 14")

clients = ["CBC", "SmallCo", "News Corp"]
emails = ["  ADMIN@CBC.ca  ", "user@smallco.com", "contact@newscorp.com"]
statuses = ["paid", "trial", "lead"]

'''client_index_1 = clients[1]
email_index_1 = emails[1]
status_index_1 = statuses[1]
'''
index = 1

client = clients[index]
email = emails[index]
status = statuses[index]

clean_email = email.strip().lower()

if "@" in clean_email:
    at_pos = clean_email.find("@")
    username = clean_email[:at_pos]
    domain = clean_email[at_pos+1:]
    
    print(f"client: {client}")
    print(f"email: {clean_email}")
    print(f"username: {username}")
    print(f"domain: {domain}")
    print(f"status: {status}")