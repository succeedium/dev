print("task 1")
# Task 1 — Create the dataset file

with open("Code/Dominika/usage_activity.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
    file.write("tom@trialdomain.com\n")
    file.write("support@cbc.ca\n")
    file.write("demo@newlead.com\n")
    print("File created")

print("task 2")
#Task 2 — Read and print all saved emails

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        email = line.strip()
        print(email)

print("task 3")
#Task 3 — Count saved emails
count = 0
with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        if line.strip() != "":
            email = line.strip()
            count += 1
    print(f"Total saved emails: {count}")

print("task 4")
#Task 4 — Add one email from input
new_email = input("Enter email: ")

clean_email = new_email.strip().lower()

with open("Code/Dominika/usage_activity.txt", "a") as file:
    file.write(clean_email + "\n")
    print("email saved")

print("task 5")
#Task 5 — Read the file after appending

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()
    for line in lines:
        print(line.strip())

print("task 6")
#Task 6 — Skip blank lines

with open("Code/Dominika/usage_activity.txt", "a") as file:
    file.write("\n")

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        clean_line = line.strip()

        if clean_line != "":
            print(clean_line)

print("task 7")
#Task 7 — Print only SmallCo emails

keyword = "smallco.com"

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        if keyword in line:
            print(line.strip())

print("task 8")
#Task 8 — Print valid-looking and invalid-looking emails

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        email = line.strip()
        if line.strip() != "":
            if "@" in email:
                print(f"valid-looking email: {email}")
            else:
                print(f"invalid-looking email: {email}")

print("task 9")
#Task 9 — Extract domains from saved emails

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        email = line.strip()
        if email != "" and "@" in email:
            at_pos = email.find("@")
            domain = email[at_pos+1:]
            print(domain)

print("task 10")
#Task 10 — Mini dataset report

to_records_count = 0
valid_count = 0
invalid_count = 0
smallco_count = 0
keyword = "smallco.com"

with open("Code/Dominika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        clean_email = line.strip().lower()
        if clean_email == "":
            continue
        to_records_count += 1

        if "@" in clean_email:
            valid_count += 1
        else:
            invalid_count += 1

        if keyword in clean_email:
            smallco_count += 1

print("Dataset report")
print(f"Total records: {to_records_count}")
print(f"Valid-looking emails: {valid_count}")
print(f"invalid-looking emails: {invalid_count}")
print(f"SmallCo emails: {smallco_count}")