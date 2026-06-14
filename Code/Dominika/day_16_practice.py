print("task 1")
#task 1
usage_record = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}
print(usage_record["email"])
print(usage_record["date"])

print("task 2")
#Task 2 — Three usage records
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"}
]
print(usage_records)

print("task 3")
#Task 3 — First record details
'''
Using the usage_records list from Task 2:

Store the first record in a variable named first_record.
Print first_record.
Print the first record's email.
Print the first record's date.'''

first_record = usage_records[0]

print(first_record)

print(first_record["email"])
print(first_record["date"])

print("task 4")
#Task 4 — Print all usage emails

for record in usage_records:
    print(record["email"])

print('task 5')
#Task 5 — Print usage summary sentences
'''Loop through usage_records and print a sentence for each record.

Expected style:

alice@smallco.com used TeamOne on 2026-04-01'''
for record in usage_records:
    print(f'{record["email"]} used TeamOne on {record["date"]}')
print("task 6")
#Task 6 — Client records
'''
Create a list named clients with three client dictionaries.

Use these records:

SmallCo — 8-user — smallco.com
CBC — unlimited — cbc.ca
Trial Account — trial — trialdomain.com
Each dictionary should have these fields:

name
plan
primary_domain
Loop through the list and print each client name.'''

clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC", "plan": "unlimited", "primary_domain": "cbc.ca"},
    {"name": "Trial Account", "plan": "trial", "primary_domain": "trialdomain.com"}

]
for client in clients:
    print(client["name"])

print("task 7")

'''Task 7 — Client plan summary
Using the clients list from Task 6, print a sentence for each client.

Expected style:

SmallCo uses the 8-user plan
CBC uses the unlimited plan
Trial Account uses the trial plan'''
for client in clients:
    print(f'{client["name"]} uses the {client["plan"]} plan')

print("task 8")
#Task 8 — Filter SmallCo usage records
'''Loop through usage_records and print only the emails that contain:

smallco.com
Expected output:

alice@smallco.com
bob@smallco.com'''
for record in usage_records:
    if "@smallco.com" in record["email"]:
        print(record["email"])

print("task 9")
#Task 9 — Search client by exact name
'''Create a variable:

search_name = "CBC"
Loop through clients.

If the client's name equals search_name, print:

the client name
the plan
the primary domain'''
search_name = "CBC"
for client in clients:
    if client["name"] == search_name:
        print(client["name"])
        print(client["plan"])
        print(client["primary_domain"])

print("task 10")
#Task 10 — Search clients by keyword
'''Task 10 — Search clients by keyword
Create a variable:

keyword = "trial"
Loop through clients.

Print the names of clients where the keyword appears in the client name.

The search should be case-insensitive.

Hint:

keyword.lower() in client["name"].lower()
'''
keyword = "trial"

for client in clients:
    if keyword.lower() in client["name"].lower():
        print(client["name"])

print("task 11")
#Task 11 — Add a new usage record
'''
Add this new record to usage_records using append():

new.user@smallco.com — 2026-04-03
After adding it, print the total number of usage records using len().

Then print all usage emails again.'''
usage_records.append({"email": "new.user@smallco.com", "date": "2026-04-03"})

print(len(usage_records))
for record in usage_records:
    print(record["email"])

print("task 12")
#Task 12 — Challenge: print trial-domain usage
'''
Loop through usage_records and print only emails that contain:

trialdomain.com
Expected output:

tom@trialdomain.com'''
for record in usage_records:
    if "trialdomain.com" in record["email"]:
        print(record["email"])