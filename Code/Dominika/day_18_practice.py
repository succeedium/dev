# Task 1 — Create emails.txt
print("task 1")

with open("emails.txt", "w") as file:
    file.write("alice@smallco.com\n")
    file.write("bob@smallco.com\n")
    file.write("tom@trialdomain.com\n")
    print("emails.txt created")

print("task 2")

with open("emails.txt", "r") as file:
    text = file.read()
print(text)

print("task 3")
with open("emails.txt", "r") as file:
    lines = file.readlines()
    for line in lines:
        email = line.strip()
        print(email)

print("task 4")

with open("emails.txt", "a") as file:
    file.write("support@cbc.ca\n")

with open("emails.txt", "r") as file:
    print(file.read())

print("task 5")

email = input("Enter email: ")
with open("emails.txt", "a") as file:
    file.write(email + "\n")
    
print("Email saved.")

print("task 6")

clean_email = input("enter email: ").strip().lower()
with open("emails.txt", "a") as file:
     file.write(clean_email + "\n")
    
with open("emails.txt", "r") as file:
        print(file.read())

print("task 7")

with open("emails.txt", "r") as file:
     lines = file.readlines()
count = 0

for line in lines:
     email = line.strip()
     if email !="":
          count = count + 1
print(f"total saved emails:",count)

print("task 8")

with open("notes.txt", "w") as file:
     file.write("Today I learned about simple text files, I learned that to make a file you write """"with open("notes.txt", "w")""""\n")
     file.write("I also learned that \\n means new line. \n")
with open("notes.txt", "r") as file:
    read = file.read()
    print(read)

print("task 9")
     
with open("email_dataset.txt", "w") as file:
     file.write("dom@gmail.com\n")
     file.write("vlad@gmail.com\n")
     file.write("sas@smallco.com\n")
     file.write("rod@smallco.com\n")
     file.write("fow@cbc.ca\n")
     file.write("doordash@trialdomain.com\n")
     file.write("hiia@newlead.com\n")
with open("email_dataset.txt", "r") as file:
     print(file.read())

keyword = "smallco.com"
with open("email_dataset.txt", "r") as file:
     for line in file:
        email = line.strip()
        if keyword in email:
            print(email)

print("task 11")

email = input("Enter email TeamOne User: ")
clean_email = email.strip().lower()
with open("email_dataset.txt", "a") as file:
     file.write(clean_email + "\n")
     
print("all saved emails")

with open("email_dataset.txt" ,"r") as file:
     dataset_content = file.read()
print(dataset_content)

with open("email_dataset.txt", "r") as file:
     lines = file.readlines()

count = 0
for line in lines:
     if line.strip() != "":
          count = count + 1
print(f"total count of non-empty emails:", {count})

print("task 12")

'''Why is appending to a file useful for a program that collects activity data?
Example:'''

# Appending is useful because you can add content in the file whenever needed, and its a really simple way to do so.