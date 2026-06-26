email = input("Enter email TeamOne User: ")
clean_email = email.strip().lower()
with open("email_dataset.txt", "a") as file:
     file.write(clean_email + "\n")
     
print("all saved emails")

with open("email_dataset.txt" ,"r") as file:
     dataset_content = file.read()
print(dataset_content)

with open("dataset_content", "r") as file:
     lines = file.readlines()

count = 0
for line in lines:
     if line.strip() != "":
          count = count + 1
print(f"total count of non-empty emails:", {count})