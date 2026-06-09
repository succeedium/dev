# Task 1 — One client record
print("task 1")

'''Task 1 — One client record
Create one dictionary called client with these keys:

name
plan
contact_email
Use any realistic values.

Print each value separately.'''

client = {
    "name": "dom",
    "plan": "free",
    "contact_email": "dom@gmail.com"
}

print(client["name"])
print(client["plan"])
print(client["contact_email"])

#Task 2 — One usage record
print("task 2")

'''Create one dictionary called usage with these keys:

email
date
product
Print each value separately.'''
usage = {
    "email": "dom@gmail.com",
    "date": "05/22/2010",
    "product": "phone"
}
print(usage["email"])
print(usage["date"])
print(usage["product"])

#Task 3 — Mini description
print("task 3")

'''Create a dictionary:

client = {
    "name": "SmallCo",
    "plan": "trial"
}
Print a sentence like:

SmallCo is on a trial plan.
Use an f-string and values from the dictionary.'''

client = {
    "name": "SmallCo",
    "plan": "trial"
}

print(f"{client["name"]} is on a {client["plan"]} plan.")

#Task 4 — Add a missing email
print("task 4")
'''
Task 4 — Add a missing email
Start with:

client = {
    "name": "SmallCo",
    "plan": "trial"
}
Add a new key called contact_email with value:

"owner@smallco.com"
Print the final dictionary.'''

client = {
    "name": "SmallCo",
    "plan": "trial"
}
client["contact_email"] = "owner@smallco.com"
print(client)

#Task 5 — Change the plan
print("task 5")
'''Start with:

client = {
    "name": "SmallCo",
    "plan": "trial"
}
Change the plan from "trial" to "paid".

Print the final dictionary.
'''
client = {
    "name": "SmallCo",
    "plan": "trial"
}
client["plan"] = "paid"
print(client)

print("task 6")
#Task 6 — Check if email exists
'''Start with:

client = {
    "name": "SmallCo",
    "plan": "trial"
}
Use if to check whether the key "contact_email" exists in the dictionary.

If it exists, print the email.

Otherwise, print:

contact email is missing'''

client = {
    "name": "SmallCo",
    "plan": "trial"
}
if "contact_email" in client:
    print(client["email"])
else:
    print("contact email is missing")

#Task 7 — Usage record domain
print("task 7")
'''Create a usage dictionary:

usage = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}
Use the email from the dictionary.

Extract the domain using either:

.find() and slicing
or .split("@")
Print the domain.

Expected result:

smallco.com'''

usage = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}
at_pos = usage["email"].find("@")
domain = usage["email"][at_pos+1:]
print(domain)

print("task 8")
#Task 8 — Client with different value types
'''Create a dictionary called client with:

name as a string
plan as a string
max_users as an integer
active as a boolean
Print all four values.'''

client = {
    "name": "dom",
    "plan": "free",
    "max_users": 8,
    "active": "True"
}
print(client)

#Task 9 — Simple status check
print("task 9")
'''Create a dictionary:

client = {
    "name": "SmallCo",
    "plan": "trial"
}
Use if / else:

if the plan is "trial", print "trial client"
otherwise, print "not trial"
Use the value from the dictionary, not a separate variable.'''

client = {
    "name": "SmallCo",
    "plan": "trial"
}

if "plan" in client == "trial":
    print("trial client")
else:
    print("not trial")

print("task 10")
'''Task 10 — Mini account card
Create a dictionary called client with:

name
plan
primary_domain
contact_email
Print a small account card like this:

Client: SmallCo
Plan: trial
Domain: smallco.com
Contact: owner@smallco.com
Use dictionary values in the printed lines.'''

client = {
    "name": "SmallCo",
    "Plan": "Trial",
    "primary_domain": "smallco.com",
    "contact_email": "owner@smallco.com",
}

print(f"Client: {client['name']}")
print(f"Plan: {client['Plan']}")
print(f"Domain: {client['primary_domain']}")
print(f"Contact: {client['contact_email']}") 

