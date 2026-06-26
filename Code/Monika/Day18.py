# Task 1 — Create emails.txt

emails = ["alice@smallco.com","bob@smallco.com","tom@trialdomain.com"]

with open("emails.txt", "w") as file:
     for email in emails:
       file.write(email + "\n")
print("emails.txt created")


# Task 2 — Read the whole file

with open("emails.txt", "r") as file:
    contents = file.read()
    print(contents)

#Task 3 — Read lines and clean them

with open("emails.txt", "r") as file:
    lines = file.readlines()
    for line in lines:
        email = line.strip()
        print(email)

#Task 4 — Append one hardcoded email

with open("emails.txt", "a") as file:
      file.write("support@cbc.ca\n")

with open("emails.txt", "r") as file:
       print(file.read())

#Task 5 — Add one email from input

email1 = input("What email would you like to add? ")

with open("emails.txt", "a") as file:
     file.write(email1 + "\n")
     print("email saved")

#Task 6 — Add a cleaned email from input

email1 = input("What email would you like to add? ").strip().lower()

with open("emails.txt", "a") as file:
     file.write(email1 + "\n")
     print("email saved")

with open("emails.txt", "r") as file:
       print(file.read())

#Task 7 — Count saved emails

with open("emails.txt", "r") as file:
     line = len(file.readlines())
     print(f"There are {line} saved emails.")

#Task 8 — Create a notes file
with open("notes.txt", "w") as file:
     i_learned = """I learned about creating files and I
learned about reading files. """
     file.write(i_learned)

with open("notes.txt", "r") as file:
     file_reading = file.read()
     print(file_reading)

#Task 9 — Create a larger email dataset

with open("email_dataset.txt", "w") as file:
     emails = ["Jay@smallco.com","layla@smallco.com","robin@cbc.ca", "parker@trialdomain.com","lola@newlead.com", "marvin@newlead.com"]
     for email in emails:
          file.write(email + "\n")
with open("email_dataset.txt", "r") as file:
     lines = file.readlines()
     for line in lines:
         email = line.strip()
         print(email)

#Task 10 — Filter the dataset
with open("email_dataset.txt", "r") as file:
          lines = file.readlines()
          for line in lines:
           email = line.strip()
           if "smallco.com" in email:
               print(email)

#Task 11 — Mini database growth demo

Tm_email = input("Enter a TeamOne email: ")
clean_email = Tm_email.strip().lower()
email_count = 0

with open("email_dataset.txt", "a") as file:
     file.write(clean_email + "\n")
with open("email_dataset.txt", "r") as file:
       for line in file.readlines():
            cleaned_line = line.strip()
            if cleaned_line:
               print(cleaned_line)
              
               email_count += 1
               
    
print("Total number of non-empty saved emails:", email_count)

#Append is useful because it adds new values without having to rewrite all the value previously stored.
