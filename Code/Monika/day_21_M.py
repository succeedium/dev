# Task 1 — Plan classifier

plan = "Trial"

if plan == "unlimited":
    print("Enterprise client.")
elif plan == "8-user":
    print("Small team client.")
elif plan == "Trial":
    print("Trial client")
else: 
    print("Unknown plan.")

plan = "Legendary plan"

if plan == "unlimited":
    print("Enterprise client.")
elif plan == "8-user":
    print("Small team client.")
elif plan == "Trial":
    print("Trial client")
else: 
    print("Unknown plan.")

plan = "unlimited"

if plan == "unlimited":
    print("Enterprise client.")
elif plan == "8-user":
    print("Small team client.")
elif plan == "Trial":
    print("Trial client")
else: 
    print("Unknown plan.")

# Task 2 — Valid-looking email check

email = "didenko.consulting@succeedium.ca"

contains_at = "@" in email
contains_dot = "." in email

if contains_at == True and contains_dot == True:
    print("Valid-looking email")
else: print("Invalid-looking email")

#Task 3 — Follow-up status check

status = "lead"

if status == "trial" or status == "lead":
    print("Needs follow up.")
else: print("No follow up needed.")

status = "trial"

if status == "trial" or status == "lead":
    print("Needs follow up.")
else: print("No follow up needed.")

status = "client"

if status == "trial" or status == "lead":
    print("Needs follow up.")
else: print("No follow up needed.")

#Task 4 — Known domain check

known_domains = ["smallco.com", "cbc.ca", "newscorp.com"]

domain = "smallco.com"

if domain in known_domains:
    print("known client domain")
else:
    print("domain unknown")


#Task 5 — Unknown domain check with not in

known_domains = ["smallco.com", "cbc.ca", "newscorp.com"]

domain = "newlead.com"

if domain not in known_domains:
    print("Potential trial or lead domain")
else: print("Known client domain.")

#Task 6 — Helper variables for conditions

email = "alice@smallco.com"

has_at = "@" in email
has_dot = "." in email

if has_at == True and has_dot == True:
    print("Valid- looking email.")
else:
    print("invalid- looking email.")



#Task 7 — Activity records: print valid-looking emails

usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@cbc.ca", "date": "2026-04-01"},
    {"email": "demo@newlead.com", "date": "2026-04-02"},
    {"email": "bad-email", "date": "2026-04-02"}
]

for record in usage_records:
    email = record["email"]
    has_at = "@" in email
    has_dot = "." in email
    if has_at == True and has_dot == True:
        print(email)

#Task 8 — Activity records: known vs unknown domains

def get_domain(email):
    return email[email.find("@") + 1:]

known_domains = ["smallco.com", "cbc.ca"]
 
for record in usage_records:
    email = record["email"]
    has_at = "@" in email
    has_dot = "." in email
    if has_at == True and has_dot == True:
        domain = get_domain(email)
        if domain in known_domains:
            print(f"Known: {domain}")
        else: print(f"unknown: {domain}")

#Task 9 — Client plan report

clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC", "plan": "unlimited", "primary_domain": "cbc.ca"},
    {"name": "Demo Lead", "plan": "trial", "primary_domain": "newlead.com"}
]

for record in clients:
    name = record["name"]
    plan = record["plan"]
    if plan == "unlimited":
     print(f"{name}: Enterprise client")
    elif plan == "8-user":
        print(f"{name}: Small team client")
    elif plan == "trial":
        print(f"{name}: Trial client")
    else: print("unknown plan")


#Task 10 — Mini boolean activity report

known_domains = ["smallco.com", "cbc.ca"]

usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@cbc.ca", "date": "2026-04-01"},
    {"email": "demo@newlead.com", "date": "2026-04-02"},
    {"email": "bad-email", "date": "2026-04-02"}
]


#section one Valid-looking emails:

for record in usage_records:
    email = record["email"]
    has_at = "@" in email
    has_dot = "." in email
    if has_at == True and has_dot == True:
        print(email)


#section two Known domains:

for record in usage_records:
    email = record["email"]

    if "@" in email and "." in email:
        domain = email[email.find("@") + 1:]

        if domain in known_domains:
            print(domain)

#section three unknown domains
    
for record in usage_records:
    email = record["email"]

    if "@" in email and "." in email:
        domain = email[email.find("@") + 1:]

        if domain not in known_domains:
            print(domain)










    






