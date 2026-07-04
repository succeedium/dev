# Task 1 — Create the dataset file
with open("m.email_dataset.txt" , "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
    file.write("tom@trialdomain.com\n")
    file.write("support@cbc.ca\n")

    file.write("demo@newlead.com\n")
print("files have been created.\n")

#Task 2 — Read and print all saved emails

with open("m.email_dataset.txt", "r") as file:
    lines = file.readlines()
    for line in lines:
        print(line.strip())

#Task 3 — Count saved emails

count = 0

with open("m.email_dataset.txt","r") as file:
    lines = file.readlines()
    for line in lines:
        if " " not in line:
            count = count + 1

    print(f"There are: {count} saved emails.")

#Task 4 — Add one email from input
email1 = input("What email would you like to add? ").strip().lower()
with open("m.email_dataset.txt", "a") as file:
     file.write(email1 + "\n")
     print("email saved.")

#Task 5 — Read the file after appending

with open("m.email_dataset.txt", "r") as file:
     lines = file.readlines()
     for line in lines:
         print(line.strip().lower())

# Task 6 — Skip blank lines

with open("m.email_dataset.txt" , "a") as file:
    file.write("\n")

with open("m.email_dataset.txt", "r") as file:
    lines = file.readlines()
    for line in lines:
      if line.strip() != "":
            print(line.strip())

#Task 7 — Print only SmallCo emails

with open("m.email_dataset.txt", "r") as file:
    lines = file.readlines()
    for line in lines:
        if "smallco" in line.strip().lower():
            print(line.strip())
    
#Task 8 — Print valid-looking and invalid-looking emails

with open("m.email_dataset.txt","r") as file:
  lines = file.readlines()
  for line in lines:
      clean = line.strip()

      if clean == "":
            continue
      
      if "@" in clean and " " not in clean:
        print(f"Valid-looking: {clean}")
      else: print(f"Invalid-looking: {clean}")

#Task 9 — Extract domains from saved emails

with open("m.email_dataset.txt","r") as file:
    lines = file.readlines()
    for line in lines:
        if "@" in line:
            at_pos = line.find("@")
            domain = line[at_pos + 1:]
            print(f"Domain is {domain}")

#Task 10 — Mini dataset report

valid_count = 0
invalid_count = 0
smallco_count = 0
total_records = 0 

with open("m.email_dataset.txt","r") as file:
    for line in file:
        email = line.strip()

        if email == "":
            continue

        total_records = total_records + 1


        if "@" in email:
            valid_count = valid_count + 1

            if "smallco" in email.lower():
                smallco_count += 1
        else:
              invalid_count += 1

print("Dataset report")
print(f"Total records: {total_records}")
print(f"Valid-looking emails: {valid_count}")
print(f"Invalid-looking emails: {invalid_count}")
print(f"SmallCo emails: {smallco_count}")