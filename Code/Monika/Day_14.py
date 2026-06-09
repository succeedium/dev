# Task 1 — One client record

client = {"name": "pinterest",
          "plan": "paid",
         "email" : "company.pinterest@gmail.com"  }

print(client["name"])
print(client["plan"])
print(client["email"])

# Task 2 - One usage record

usage = {"email": "doordash.company@gmail.com",
"date" : "July 10",
"product": "TeamOne"}

print(usage["email"])
print(usage["date"])
print(usage["product"])

# Task 3 - Mini description

client = {
    "name": "SmallCo",
    "plan": "trial"
}

print(f"{client['name']} is on a {client["plan"]} plan.")

# Task 4 — Add a missing email

client_dictionary = {
    "name": "SmallCo",
    "plan": "trial"
}

client_dictionary["contact_email"] = "owner@smallco.com"

print(client_dictionary)

# Task 5 — Change the plan

client = {
    "name": "SmallCo",
    "plan": "trial"
}

client["plan"] = "paid"

print(client)

# Task 6 — Check if email exists

client = {
    "name": "SmallCo",
    "plan": "trial"
}

if "contact_email" in client:
    print(client["contact_email"])
else: 
    print("Client email is missing")

# Task 7 — Usage record domain

usage = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}

usage = {
    "email": "alice@smallco.com",
    "date": "2026-04-01"
}

domain = usage["email"].split("@")[1]
print(domain)

#Task 8 — Client with different value types

client = {
    "name": "SmallCo",
    "plan": "trial",
    "max_users" : 7,
    "active": True
}

print(client)

# Task 9 — Simple status check

client = {
    "name": "SmallCo",
    "plan": "trial"
}

if client["plan"] == "trial":
    print("Trial Client")
else:
    print("Not trial.")

# Task 10 — Mini account card

client = {
    "name": "SmallCo",
    "plan": "trial",
    "primary_domain": "smallCo.com",
    "contact_email": "client@smallCo.com"
}

print(f"""
Client: {client["name"]}
Plan: {client['plan']}
Domain: {client['primary_domain']}
Contact: {client["contact_email"]}""")





