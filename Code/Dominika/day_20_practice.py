print("task 1")
# Task 1 — Create the dataset file

with open("Code/Dominika/usage_activity.txt", "w") as file:
    file.write("alice@smallco.com,2026-04-01\n")
    file.write("bob@smallco.com,2026-04-02\n")
    file.write("tom@trialdomain.com,2026-04-03\n")
    file.write("support@cbc.ca,2026-04-04\n")
    file.write("demo@newlead.com,2026-04-05\n")
    print("File created")

print("task 2")
#Task 2 — Read and print all saved emails

with open("Code/Dominika/usage_activity.txt", "r") as file:
    text = file.read()
    print(text)

print("task 3")
#Task 3 — Print email and date separately

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        if line.strip() != "":
            parts = line.strip().split(",")
            email = parts[0]
            date = parts[1]
            print(f"email: {email} date: {date}")

print("task 4")
#Task 4 — Add one email from input
new_email = input("Enter email: ")
new_date = input("Enter date (YYYY-MM-DD): ").strip()
clean_email = new_email.strip().lower()

with open("Code/Dominika/usage_activity.txt", "a") as file:
    # FIXED: removed extra spaces around comma and before \n
    file.write(f"{clean_email},{new_date}\n")
    print("record saved")

print("task 5")
#Task 5 — Read the file after appending

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()
    for line in lines:
        clean_line = line.strip()
        if clean_line != "":
            parts = clean_line.split(",")
            email = parts[0].strip()
            date = parts[1].strip()
            print(f"TeamOne user {email} was active on {date}")

print("task 6")
#Task 6 — Create dictionary for each line

with open("Code/Dominika/usage_activity.txt", "a") as file:
    file.write("\n")

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        clean_line = line.strip()

        if clean_line != "":
            parts = clean_line.split(",")
            if len(parts) == 2:
                record = {
                    "email": parts[0].strip(),
                    "date": parts[1].strip()
                }
                print(record)

print("task 7")
#Task 7 — Store records in usage_records list
usage_records = []

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()
    
    for line in lines:
        clean_line = line.strip()
        if clean_line != "":
            parts = clean_line.split(",")
            if len(parts) == 2:
                record = {
                    "email": parts[0].strip(),
                    "date": parts[1].strip()
                }
                usage_records.append(record)

print("usage_records list:")
print(usage_records)

print("task 8")
#Task 8 — Print SmallCo emails from usage_records
keyword = "smallco.com"

for record in usage_records:
    if keyword in record["email"]:
        print(f"SmallCo user: {record['email']} active on {record['date']}")

print("task 9")
#Task 9 — Extract domains from saved emails
for record in usage_records:
    email = record["email"]
    if email != "" and "@" in email:
        at_pos = email.find("@")
        domain = email[at_pos+1:]
        print(domain)

print("task 10")
#Task 10 — Handle bad lines safely

with open("Code/Dominika/usage_activity_with_bad_lines.txt", "w") as file:
    file.write("alice@smallco.com,2026-04-01\n")
    file.write("bad-line-without-comma\n")
    file.write("bob@smallco.com,2026-04-02\n")
    file.write("\n")
    file.write("demo@newlead.com,2026-04-05\n")

with open("Code/Dominika/usage_activity_with_bad_lines.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        clean_line = line.strip()
        if clean_line == "":
            continue
        
        parts = clean_line.split(",")
        if len(parts) == 2:
            email = parts[0].strip()
            date = parts[1].strip()
            print(f"Good line -> email: {email}, date: {date}")
        else:
            print(f"Skipping bad line: {clean_line}")

print("task 11")
#Task 11 — Store valid records in clean_records list

clean_records = []

with open("Code/Dominika/usage_activity_with_bad_lines.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        clean_line = line.strip()
        if clean_line != "":
            parts = clean_line.split(",")
            if len(parts) == 2:
                record = {
                    "email": parts[0].strip(),
                    "date": parts[1].strip()
                }
                clean_records.append(record)

print("clean records list:")
print(clean_records)

print("task 12")
#Task 12 — Dataset report

valid_count = len(clean_records)
smallco_count = 0

for record in clean_records:
    if "smallco.com" in record["email"]:
        smallco_count += 1

print("Dataset report")
print(f"Total valid records: {valid_count}")
print(f"SmallCo records: {smallco_count}")