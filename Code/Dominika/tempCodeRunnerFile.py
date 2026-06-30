
print("task 10")
#Task 10 — Mini dataset report

'''Create a small report from email_dataset.txt.

The report should print:

total non-empty saved records
number of valid-looking emails
number of invalid-looking emails
number of smallco.com emails
Example output:

Dataset report
Total records: 6
Valid-looking emails: 5
Invalid-looking emails: 1
SmallCo emails: 2'''
to_records_count = 0
valid_count = 0
invalid_count = 0
smallco_count = 0
keyword = "SmallCo"
with open("email_dataset.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        clean_email = line.strip()

        if clean_email == "":
            continue

        total_records = + 1

        if "@" in clean_email:
            valid_count = + 1

        if clean_email != "@":
            invalid_count = + 1

        if keyword in clean_email:
            smallco_count = + 1

print("Dataset report")

print(f"Total records:, {total_records}")
print(f"Valid-looking emails:, {valid_count}")
print(f"Invalid-looking emails:, {invalid_count}")
print(f"SmallCo emails:, {smallco_count}")
