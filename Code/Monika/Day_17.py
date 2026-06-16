# Task 1 — Create hardcoded activity records

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date": "2026-04-02"}, {"email": "lora@doordash.com", "date" : "2026-07-03"}]
print(usage_records)

# Task 2 — Create hardcoded client records

clients = [{"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"}, {"name": "DoorDash", "primary_domain": "doordash.com", "plan": "Unlimited"},{"name": "Pinterest", "primary_domain": "Pinterest.com", "plan": "Unlimited"}]
print(clients)

# Task 3 — Print all activity emails

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date": "2026-04-02"}, {"email": "lora@doordash.com", "date" : "2026-07-03"}]

for record in usage_records :
  print(record['email'])


# Task 4 — Print readable activity summaries

for record in usage_records:
      email = record["email"]
      date = record['date']
      print(f"{email} used TeamOne on {date}.")

# Task 5 — Create a normalize_email function

def normalize_email(email):
    c_email = email.strip().lower()
    return(c_email)
print(normalize_email("  Alice@SmallCo.COM  "))

# Task 6 — Create a get_domain function

def get_domain(email):
     at_pos = email.find("@")
     domain = email[at_pos + 1:]
     return(domain)

print(get_domain("alice@smallco.com"))

# Task 7 — Print each activity email with its domain
for record in usage_records:
    email = record["email"]
    at_pos = email.find("@")
    domain = email[at_pos + 1:]
    print(email)
    print(domain)
    print(f"{email} belongs to {domain}")

    
#Task 8 — Search clients by exact company name

search_name = "SmallCo"

for client in clients: 
    plan = client["plan"]
    name = client["name"]
    domain = client["primary_domain"]
    if search_name.strip().lower() in domain.strip().lower():
     print(name)
     print(domain)
     print(plan)

#Task 9 — Search clients by keyword

keyword = "co"
 
for client in clients:
    name = client["name"]
    if keyword.strip().lower() in client["name"].strip().lower():
        print(name)

#Task 10 Build known domains list

known_domains = []

for client in clients:
    domain = client["primary_domain"]
    known_domains.append(domain)
print(known_domains)

#Task 11  — Print known vs unknown activity

for record in usage_records:
    email = record["email"]
    at_pos = email.find("@")
    domain = email[at_pos + 1:]
    if domain in known_domains:
        print(f"Known client activity: {email}")
    else:
        print(f"Unknown or trial activity: {email}")

#Task 12 — Final mini report

for record in usage_records:
    date = record["date"]
    email = record["email"]
    at_pos = email.find("@")
    domain = email[at_pos + 1:]
    if domain in known_domains:
        status = "Known client"
    else: status = "unknown or trial"
    print(f"{email} | {date} | {domain} | {status}")
    
 
