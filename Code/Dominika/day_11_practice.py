'''Task 1 — Build an email list from empty
Start with an empty list:
emails = []
Add 4 emails using append().
Print:
the whole list
the list length using len()
'''
print("task 1")
emails = []
emails.append("admin@cbc.ca")
emails.append("user@smallco.com")
emails.append("sales@newscorp.com")
emails.append("help@test.ca")
print(emails)
print(len(emails))
'''
Task 2 — Add a new client
Start with:
clients = ["CBC", "SmallCo"]
Use append() to add "News Corp".
Print the final list.
'''
print("task 2")
clients = ["CBC", "SmallCo"]
clients.append("News Corp")
print(clients)
'''
Task 3 — Insert an important client
Start with:
clients = ["CBC", "SmallCo", "News Corp"]
Insert "DoorDash" at index 1.
Print the final list.
'''
print("task 3")
clients = ["CBC", "SmallCo", "News Corp"]
clients.insert(1, "DoorDash")
print(clients)
'''
Task 4 — Add many emails
Start with:
emails = ["admin@cbc.ca", "user@smallco.com"]
more_emails = ["sales@newscorp.com", "help@test.ca"]
Use extend() to add all more_emails into emails
print the final list
'''
print("task 4")
emails = ["admin@cbc.ca", "user@smallco.com"]
more_emails = ["sales@newscorp.com", "help@test.ca"]
emails.extend(more_emails)
print(emails)

'''
Task 5 — Compare append() and extend()
Use the same two lists:
emails = ["admin@cbc.ca"]
more_emails = ["sales@newscorp.com", "help@test.ca"]

First try append(more_emails) and print the result.
Then reset the original list and try extend(more_emails).
Write a comment explaining the difference.
'''
print("task 5")
emails = ["admin@cbc.ca"]
more_emails = ["sales@newscorp.com", "help@test.ca"]
#emails.append(more_emails)
#print(emails)
#emails.extend(more_emails)
#print(emails)
# emails.append(more_emails) puts the two items in more_emails in the emails list but just in bracets.
# emails.extend(more_emails) extends the list emails by adding the two emails in more_emails to the lsit.
'''
Task 6 — Correct one client name
Start with:
clients = ["CBC", "SmolCo", "News Corp"]

Change "SmolCo" to "SmallCo" using index 1.
Print the corrected list.
'''
print("task 6")
clients = ["CBC", "SmolCo", "News Corp"]
clients[1] = "SmallCo"
print(clients)
'''
Task 7 — Correct one email
Start with:
emails = ["admin@cbc.ca", "wrong-email", "contact@newscorp.com"]

Replace "wrong-email" with "user@smallco.com" using index 1.
Print the corrected list.
'''
print("task 7")
emails = ["admin@cbc.ca", "wrong-email", "contact@newscorp.com"]
emails[1] = "user@smallco.com"
print(emails)
'''
Task 8 — Remove a test client safely
Start with:
clients = ["CBC", "SmallCo", "Test Client", "News Corp"]

Check if "Test Client" is in the list.
If it is, remove it.
Print the final list.
'''
print("task 8")
clients = ["CBC", "SmallCo", "Test Client", "News Corp"]
if "Test Client" in clients:
    clients.remove("Test Client")
print(clients)
'''
Task 9 — Try safe remove when value is missing
Start with:
clients = ["CBC", "SmallCo", "News Corp"]

Check if "Test Client" is in the list.
If it is, remove it.
Otherwise print:
Test Client not found

Then print the final list.
'''
print("task 9")
clients = ["CBC", "SmallCo", "News Corp"]
if "Test Client" in clients:
    clients.remove("Test Client")
else:
    print("Test Client not found")
print(clients)
'''
Task 10 — Use pop() to remove by position
Start with:
clients = ["CBC", "SmallCo", "News Corp"]

Use pop(1) to remove "SmallCo".
Store it in a variable called removed_client.
Print:
the removed client
the final list
'''
print("task 10")
clients = ["CBC", "SmallCo", "News Corp"]
removed_client = clients.pop(1)
print(removed_client)
print(clients)

'''Task 11 — Use pop() to remove the last email
Start with:
emails = ["admin@cbc.ca", "user@smallco.com", "contact@newscorp.com"]

Use pop() with no index.
Store the removed email in last_email.
Print:
the removed email
the final list
'''
print("task 11")
emails = ["admin@cbc.ca", "user@smallco.com", "contact@newscorp.com"]
last_email = emails.pop()
print(last_email)
print(emails)

'''
Task 12 — Use del to delete by index
Start with:
clients = ["CBC", "SmallCo", "News Corp"]

Use del to delete the item at index 0.
Print the final list.
'''
print("task 12")
clients = ["CBC", "SmallCo", "News Corp"]
del clients[0]
print(clients)
'''
Task 13 — Count repeated domains
Start with:
domains = ["gmail.com", "yahoo.com", "gmail.com", "test.ca", "gmail.com"]

Use count() to count:
"gmail.com"
"yahoo.com"
"outlook.com"
Print all three counts.
'''
domains = ["gmail.com", "yahoo.com", "gmail.com", "test.ca", "gmail.com"]

gmail_count = domains.count("gmail.com")
yahoo_count = domains.count("yahoo.com")
outlook_count = domains.count("outlook.com")

print(gmail_count)
print(yahoo_count)
print(outlook_count)

'''
Task 14 — Count repeated statuses
Start with:
statuses = ["trial", "paid", "trial", "expired", "trial", "paid"]

Print how many times each appears:
"trial"
"paid"
"expired"
"lead"
'''
print("task 14")

statuses = ["trial", "paid", "trial", "expired", "trial", "paid"]
times_trial = statuses.count("trial")
times_paid = statuses.count("paid")
times_expired = statuses.count("expired")
times_lead = statuses.count("lead")

print(times_trial)
print(times_paid)
print(times_expired)
print(times_lead)
'''
Task 15 — Sort client names
Start with:
clients = ["DoorDash", "CBC", "Pinterest", "SmallCo"]

Print the original list.
Sort it.
Print the sorted list.
'''
print("task 15")

clients = ["DoorDash", "CBC", "Pinterest", "SmallCo"]

print(clients)

clients.sort()

print(clients)

'''Task 16 — Reverse client names
Start with:
clients = ["CBC", "DoorDash", "Pinterest", "SmallCo"]

Print the original list.
Reverse it.
Print the reversed list.
'''
print("task 16")
clients = ["CBC", "DoorDash", "Pinterest", "SmallCo"]
print(clients)
clients.reverse()
print(clients)

'''
Task 17 — Reverse alphabetical clients
Start with:
clients = ["DoorDash", "CBC", "Pinterest", "SmallCo"]

Sort the list.
Then reverse it.
Print the final list.
'''
print("task 17")
clients = ["DoorDash", "CBC", "Pinterest", "SmallCo"]
clients.sort()
print(clients)
clients.reverse()
print(clients)
'''
Task 18 — Build and clean an email review list
Start with an empty list.
Use append() to add:
"  ADMIN@CBC.ca  "
"bademail.com"
"user@smallco.com"

Then create:
more_emails = ["sales@newscorp.com", "  TEST@GMAIL.com  "]

Use extend() to add the extra emails.
Then replace "bademail.com" with "support@test.ca" using its index.
Finally, loop through the emails:
clean each email with .strip().lower()
print only valid-looking emails that contain @
'''
print("task 18")
emp_list = []
emp_list.append("  ADMIN@CBC.ca  ")
emp_list.append("bademail.com")
emp_list.append("user@smallco.com")

more_emails = ["sales@newscorp.com", "  TEST@GMAIL.com  "]
emp_list.extend(more_emails)
emp_list[1] = "support@test.ca"

for email in emp_list:
    clean_email = email.strip().lower()
    if "@" in clean_email:
        print(clean_email)
'''
Task 19 — Mini list maintenance report
Use:
clients = ["CBC", "Test Client", "SmallCo", "DoorDash", "CBC"]

Do the following:
print the original list
count how many times "CBC" appears
safely remove "Test Client"
append "News Corp"
sort the list
print the final list
'''
print("task 19")
clients = ["CBC", "Test Client", "SmallCo", "DoorDash", "CBC"]
print(clients)
count_CBC = clients.count("CBC")
clients.remove("Test Client")
clients.append("News Corp")

clients.sort()
print(clients)
'''
Task 20 — Challenge: email collection cleanup
Start with:
emails = []

Add these with append():
"  A@GMAIL.com  "
"bademail.com"
" C@Test.ca "

Then:
insert "first@client.com" at the beginning
extend the list with ["extra@yahoo.com", "wrong-email"]
remove "wrong-email" safely
sort the list
loop through the final list
clean each email
print only emails containing @
'''
print("task 20")
emails = []

emails.append("  A@GMAIL.com  ")
emails.append("bademail.com")
emails.append(" C@Test.ca ")

emails[0] = "first@client.com"
extra_emails = ["extra@yahoo.com", "wrong-email"]
emails.extend(extra_emails)
if "wrong-email" in emails:
    emails.remove("wrong-email")

emails.sort()
for email in emails:
    clean_email = email.strip().lower()
    if "@"in clean_email:
        print(clean_email)