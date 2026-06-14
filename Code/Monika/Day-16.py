# Task 1
usage_record = {"email": "alice@smallco.com", "date": "2026-04-01" }
print(usage_record)
print(usage_record["email"])
print(usage_record["date"])


# Task 2

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date ": "2026-04-02"}]
print(usage_records)

# Task 3

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date ": "2026-04-02"}]
print(usage_records)

first_record = usage_records[0]

print(first_record["email"])
print(first_record["date"])

# Task 4

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date ": "2026-04-02"}]

for record in usage_records:
  print(record["email"])

#Task 5

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date": "2026-04-02"}]

for record in usage_records:
   print(f"{record['email']} used TeamOne on {record['date']} .")

# Task 6

clients = [{"name":"SmallCo", "plan": "8-user", "domain": "smallco.com"}, {"name":"CBC", "plan":"unlimited", "domain":"cbc.ca"}, {"name":"Trial Account", "plan":"trial", "domain": "trialdomain.com"}]
for client in clients:
   print(client["name"])

#Task 7

clients = [{"name":"SmallCo", "plan": "8-user", "domain": "smallco.com"}, {"name":"CBC", "plan":"unlimited", "domain":"cbc.ca"}, {"name":"Trial Account", "plan":"trial", "domain": "trialdomain.com"}]
for client in clients:
    print(f"{client['name']} uses the {client['plan']} plan.")


#Task 8

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date": "2026-04-02"}]

for record in usage_records:
   if "smallco.com" in record['email'] :
      print(record["email"])

#Task 9


clients = [{"name":"SmallCo", "plan": "8-user", "domain": "smallco.com"}, {"name":"CBC", "plan":"unlimited", "domain":"cbc.ca"}, {"name":"Trial Account", "plan":"trial", "domain": "trialdomain.com"}]


search_name = "CBC"

for client in clients:
  if client['name'] == search_name:
     print(client['name'])
     print(client["plan"])
     print(client["domain"])

#Task 10
clients = [{"name":"SmallCo", "plan": "8-user", "domain": "smallco.com"}, {"name":"CBC", "plan":"unlimited", "domain":"cbc.ca"}, {"name":"Trial Account", "plan":"trial", "domain": "trialdomain.com"}]


keyword = "trial"
for client in clients:
   if keyword.lower() in client['name'].lower():
     print(client['name'])

#Task 11

usage_records.append({"email":"new.user@smallco.com", "date":"2026-04-03"})
print(len(usage_records))

for record in usage_records:
   print(record["email"])

# Task 12

usage_records = [{"email" : "alice@smallco.com", "date" : "2026-04-01"}, {"email" : "bob@smallco.com", "date": "2026-04-01"},
{"email" : "tom@trialdomain.com", "date": "2026-04-02"}]

for record in usage_records:
   if "trialdomain.com" in record["email"]:
      print(record["email"])







