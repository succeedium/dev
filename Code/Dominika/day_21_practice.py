print(" task 1")
# Task 1 — Plan classifier

plan = "trial"

if plan == "unlimited":
    print("Enterprise client")
elif plan == "8-user":
    print("Small team client")
elif plan == "trial":
    print("Trial client")
else:
    print("Unknown plan")

print("task 2")
#Task 2 — Valid-looking email check

email = "dom@gmail.com"

if "@" in email and "." in email:
    print("valid-looking email")
else:
    print("invalid-looking email")

print("task 3")
#Task 3 — Follow-up status check

status = "lead"

if status == "trial" or status == "lead":
    print("Needs follow-up")
else:
    print("No follow-up needed")

print("task 4")
#Task 4 — Known domain check

known_domains = ["smallco.com", "cbc.ca", "newscorp.com"]

domain = "smallco.com"

if domain in known_domains:
    print("Known client domain")
else:
    print("Unknown client domain")

print("task 5")
#Task 5 — Unknown domain check with not in

domain = "newlead.com"

if domain not in known_domains:
    print("Potential trial or lead domain")
else:
    print("Known client domain")

print("task 6")
#Task 6 — Helper variables for conditions

email = "alice@smallco.com"

has_at = "@" in email
has_dot = "." in email

if has_at == True and has_dot == True:
    print("valid-looking email")
else:
    print("invalid-looking email")

print("task 7")
#Task 7 — Activity records: print valid-looking emails

usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@cbc.ca", "date": "2026-04-01"},
    {"email": "demo@newlead.com", "date": "2026-04-02"},
    {"email": "bad-email", "date": "2026-04-02"}
]

for record in usage_records:
    if "@" in record["email"] and "." in record["email"]:
        print(record["email"])

print("task 8")
#Task 8 — Activity records: known vs unknown domains

def get_domain(email):
    return email[email.find("@") + 1:]

known_domains = ["smallco.com", "cbc.ca"]

for record in usage_records:
    current_email = record["email"]

    if "@" in current_email and "." in current_email:
        current_domain = get_domain(current_email)

        if current_domain in known_domains:
            print(f"known: {current_domain}")

        else:
            print(f"unknown: {current_domain}")

print("task 9")
#Task 9 — Client plan report

clients = [
    {"name": "SmallCo", "plan": "8-user", "primary_domain": "smallco.com"},
    {"name": "CBC", "plan": "unlimited", "primary_domain": "cbc.ca"},
    {"name": "Demo Lead", "plan": "trial", "primary_domain": "newlead.com"}
]

for client in clients:
    name = client["name"]
    plan = client["plan"]

    if plan == "unlimited":
        print(f"{name}: Enterprise client")
    elif plan == "8-user":
        print(f"{name}: Small team client")
    elif plan == "trial":
        print(f"{name}: Trial client")
    else:
        print(f"{name}: Unknown plan")

print("task 10")
#Task 10 — Mini boolean activity report
print("valid-looking emails:")
for record in usage_records:
    email = record["email"]
    has_at = "@" in email
    has_dot = "." in email

    if has_at and has_dot:
        print(email)

print()

print("known domains:")

for record in usage_records:
    email = record["email"]
    has_at = "@" in email
    has_dot = "." in email

    if has_at and has_dot:
        domain = get_domain(email)

        if domain in known_domains:
            print(domain)

print()

print("Unknown domains:")

for record in usage_records:
    email = record["email"]
    has_at = "@" in email
    has_dot = "." in email

    if has_at and has_dot:
        domain = get_domain(email)
        if domain not in known_domains:
            print(domain)


