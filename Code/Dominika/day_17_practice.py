print("task 1")
usage_records = [
    {"email": "alice@smallco.com", "date": "2026-04-01"},
    {"email": "bob@smallco.com", "date": "2026-04-01"},
    {"email": "tom@trialdomain.com", "date": "2026-04-02"},
    {"email": "dom@trialdomain.com", "date": "2026-04-03"},
    {"email": "mia@trialdomain.com", "date": "2026-04-02"}
]
print(usage_records)

print("task 2")
clients = [
    {"name": "SmallCo", "primary_domain": "smallco.com", "plan": "8-user"},
    {"name": "BigCo", "primary_domain": "BigCo.com", "plan": "Trial"},
    {"name": "Pinterest", "primary_domain": "pinterest.com", "plan": "8-user"}
]
print(clients)

print("task 3")

for record in usage_records:
    print(record["email"])

print("task 4")

for record in usage_records:
    print(f'{record["email"]} used Teamone on {record["date"]}')

print("task 5")

def normalize_email(email):
    clean_email = email.strip().lower()
    return clean_email

print(normalize_email("  Alice@SmallCo.COM  "))

print("task 6")
def get_domain(email):
    at_pos = email.find("@")
    domain = email[at_pos+1:]
    return domain
print(get_domain("alice@smallco.com"))

print("task 7")

for record in usage_records:
    domain = get_domain(record["email"])
    print(f'{record["email"]} belongs to {domain}')

print("task 8")

search_name = "SmallCo"
for client in clients:
    if search_name == client["name"]:
        print(client["name"])
        print(client["primary_domain"])
        print(client["plan"])

print("task 9")

keyword = "co"
for client in clients:
    if keyword.lower() in client["name"].lower():
        print(client["name"])

print("task 10")

known_domains = []
for client in clients:
    known_domains.append(client["primary_domain"])
print(known_domains)

print("task 11")
for record in usage_records:
    email = record["email"]
    domain = get_domain(record["email"])

    if domain in known_domains:
        print(f'Known client activity: {email}')

    else:
        print(f'Unknown or trial activity: {email}')

print("task 12")
for record in usage_records:
    email = record["email"]
    date = record["date"]
    domain = get_domain(email)
    if domain in known_domains:
        status = "known client"
    else:
        status = "unknown or trial"
    print(f'{email} | {date} | {domain} | {status}')