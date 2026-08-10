print("task 1")
# Task 1 - Load valid records

file_path = "Code/Dominika/usage_activity.txt"

with open(file_path, "w") as file:
    file.write("alice@smallco.com,2026-04-01\n")
    file.write("bob@smallco.com,2026-04-01\n")
    file.write("tom@trialdomain.com,2026-04-02\n")
    file.write("support@cbc.ca,2026-04-02\n")
    file.write("demo@newlead.com,2026-04-03\n")
    file.write("bad-line-without-comma\n")

usage_records = []

with open(file_path, "r") as file:
    for line in file:
        clean_line = line.strip()
        parts = clean_line.split(",")

        if len(parts) == 2:
            usage_records.append({
                "email": parts[0],
                "date": parts[1]
            })
        else:
            print(f"skipping bad line: {clean_line}")

print(usage_records)

print("task 2")
#Task 2 — Print total valid records

print(f"total valid records {len(usage_records)}")

print("task 3")
#Task 3 — Print all activity summaries

for record in usage_records:
    print(f"{record['email']} used TeamOne on {record['date']}")

print("task 4")
#Task 4 — Create a domain helper function

def get_domain(email):
    return email.split("@")[1]

print(get_domain("alice@smallco.com"))

print("task 5")
#Task 5 — Count SmallCo records

keyword = "smallco.com"
smallco_count = 0
keyword = "smallco"

for records in usage_records:
    if keyword in records["email"]:
        smallco_count += 1

print(f"smallco count: {smallco_count}")

print("task 6")
#Task 6 — Count records for one date
the_date = "2026-04-02"
date_count = 0
for records in usage_records:
    if the_date in records["date"]:
        date_count += 1
print(f"Records on 2026-04-02: {date_count}")

print("task 7")
#Task 7 — Count known and unknown domains

known_domains = ["smallco.com", "cbc.ca"]
known_count = 0
unknown_count = 0

for record in usage_records:
    domain = get_domain(record["email"])
    if domain in known_domains:
        known_count += 1
    else:
        unknown_count += 1
print(f"known-domain records: {known_count}")
print(f"unknown-domain records: {unknown_count}")

print("task 8")
#Task 8 — Print unknown-domain emails

for record in usage_records:
    domain = get_domain(record["email"])
    if domain not in known_domains:
        print(f"unknown-record domains: {record['email']}")

print("task 9")
#Task 9 — Print a final activity report

print("TeamOne Activity Report")
print("-----------------------")

print(f"Total valid records: {len(usage_records)}")
print(f"SmallCo records: {smallco_count}")
print(f"Records on {the_date}: {date_count}")
print(f"Known-domain records: {known_count}")
print(f"Unknown-domain records: {unknown_count}")

print("task 10")
# Task 10 — Add one new record and rerun the report

with open(file_path, "a") as file:
    file.write("newuser@smallco.com,2026-04-03\n")

#What changed after adding the new line?

#The total records went up from 5 to 6.
#SmallCo records went up from 2 to 3.
#Known domain records went up from 3 to 4.