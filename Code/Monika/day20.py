# Task 1 — Create usage_activity.txt

with open("code/Monika/usage_activity.txt" , "w") as file:
 file.write("alice@smallco.com,2026-04-01\n")
 file.write("bob@smallco.com,2026-04-01\n")
 file.write("tom@trialdomain.com,2026-04-02\n")
 file.write("support@cbc.ca,2026-04-02\n")
 file.write("demo@newlead.com,2026-04-03\n")

# Task 2 — Read and print the raw file

with open("code/Monika/usage_activity.txt", "r") as file:
 lines = file.read()
 print(lines)

# Task 3 — Read lines and split them

with open("code/Monika/usage_activity.txt" , "r") as file:
 lines = file.readlines()
 for line in lines:
   line = line.strip()
   parts = line.split(",")
   print(parts)

# Task 4 — Print email and date separately


with open("code/Monika/usage_activity.txt" , "r") as file:
 lines = file.readlines()

 for line in lines: 
   line = line.strip()
   parts = line.split(",")
   email = parts[0]
   date = parts[1]
   print(f"Email: {email}")
   print(f"Date: {date}")

# Task 5 — Print activity summary sentences
 with open("code/Monika/usage_activity.txt" , "r") as file:
  lines = file.readlines() 
  for line in lines:
   line = line.strip()
   parts = line.split(",")
   email = parts[0]
   date = parts[1]
   print(f"{email} used TeamOne on {date}.")

# Task 6 — Convert one line into a dictionary
with open("code/Monika/usage_activity.txt" , "r") as file:
  lines = file.readlines() 
  for line in lines:
   line = line.strip()
   parts = line.split(",")
   email = parts[0]
   date = parts[1]
  
records = {"email": parts[0],
           "date": parts[1]}

print(records)

# Task 7 — Convert the whole file into a list of dictionaries

usage_records = []
with open("code/Monika/usage_activity.txt" , "r") as file:
  lines = file.readlines() 
  for line in lines:
   line = line.strip()
   parts = line.split(",")
   email = parts[0]
   date = parts[1]

   records = {"email": parts[0],
           "date": parts[1]}
   
   usage_records.append(records)
   print(usage_records)

   # Task 8 — Print only the emails


usage_records = []

with open("code/Monika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        line = line.strip()
        parts = line.split(",")

        record = {
            "email": parts[0],
            "date": parts[1]
        }

        usage_records.append(record)

for record in usage_records:
    print(record["email"])

#Task 9 — Filter SmallCo records

usage_records = []

with open("code/Monika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
        line = line.strip()
        parts = line.split(",")

        record = {
            "email": parts[0],
            "date": parts[1]
        }

        usage_records.append(record)

        if "smallco.com" in record["email"]:
         print("SmallCo activity:", record["email"], "on", record["date"]) 

#Task 10 — Skip bad lines safely

with open("code/Monika/usage_activity_with_bad_lines.txt", "w") as file:
    file.write("alice@smallco.com,2026-04-01\n")
    file.write("bad-line-without-comma\n")
    file.write("bob@smallco.com,2026-04-01\n")
    file.write("another bad line\n")

with open("code/Monika/usage_activity_with_bad_lines.txt", "r") as file:
   lines = file.readlines()
   for line in lines:
     line = line.strip()
     parts = line.split(",")

     if len(parts) == 2:
       email = parts[0]
       date = parts[1]

       print(email, date)

     else:
       print(f"Skipping bad line: {line}")

# Task 11 — Show current working directory

import os
print(os.getcwd())

print("This is where Python reads and writes simple file names by default.")

#Task 12 — Mini activity loader

usage_records = []

with open("code/Monika/usage_activity.txt", "r") as file:
    lines = file.readlines()

    for line in lines:
      line = line.strip()
      parts = line.split(",")

      if len(parts) == 2:
        record = { "email": parts[0],
        "date": parts[1] }

        usage_records.append(record)

        print("Total records:", len(usage_records))

        for record in usage_records:
          print(f"{record['email']} used TeamOne on {record['date']}.")

          for record in usage_records:
            if "smallco.com" in record["email"]:
                 print(f"SmallCo activity: {record['email']} on {record['date']}")

