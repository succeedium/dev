#task one
email_1 = " FIrst.laSt@gmail.com "
clean_email_1 = email_1.strip().lower()
Username_one = clean_email_1[0:clean_email_1.find("@")]
domain_one = clean_email_1[clean_email_1.find("@") + 1: ]
if "@" in clean_email_1:
    print(clean_email_1)
    print(f"Domain: {domain_one}")
    print(f"Username: {Username_one}")
else:
    print("Invalid")

 #task two
Company_name_one = "Didenko.consuting"
company_email_one = "  Didenko.consulting@succeedium.com"
clean_comp_email_one = company_email_one.strip().lower()
is_paid = True
print(f"Email: {clean_comp_email_one}")
if is_paid == True:
    print("Paid account!")
else:
    print("Trial account.")

#TaskThree
email2 = "  dOMinikA@School.org  "
clean_email2 = email2.strip().lower()
if "@" in clean_email2:
    print(clean_email2[0:clean_email2.find("@")].capitalize())
else:
    print("Invalid email.")

#Taskfour
Text = "Big Blue Company"
first_space = Text.find(" ")
Rest = Text[first_space + 1:]
second_space = Rest.find(" ") 
full_second_space  = first_space + second_space + 1

print(first_space)
print(full_second_space)
print(Text[first_space + 1: full_second_space ])

#Task five
print('------ TASK 6')
Text_two = "Green Apple Juice"
First_space2 = Text_two.find(" ")
Rest_two = Text_two[First_space2 + 1:]
second_space_two = Rest_two.find(" ")
full_second_space_two = First_space2 + second_space_two + 1

print(Text_two[First_space2 + 1 : full_second_space_two])

#Task six

email3 = "first.lastgmail.com"
clean_email3 = email3.strip().lower()
if "@" in email3:
    Username_two = email3[:email3.find("@")]
    dot_pos = email3.find(".")
    print(f"First name: {email3[:dot_pos]}")
    print(f"Last name: {email3[dot_pos + 1:email3.find("@")]}")

    if "." in Username_two: 
        print("username has no dot")

#Task seven

email4 = "student@test.ca"

if "@" in email4:
    domain_two = email4[email4.find("@") + 1:]
    dot_pos_two = domain_two.find(".")
    print(domain_two[:dot_pos_two])
    print(domain_two[dot_pos_two +1:])

#Task eight
email_5 =  "user@@gmail.com"
pos_at = email_5.find("@")
second_at = "@" in email_5[pos_at + 1:]
if second_at:
    print("Has second @")
else:
    print("Only one @")

#Task nine

email6 = "first.last@yahoo.com"
if "@" in email6:
    username3 = email6[:email6.find("@")]
    domain3 = email6[email6.find("@")+1:]
    if "." in username3:
        print("Username has dot.")
    else:
        print("Username has no dot.")
    if "." in domain3:
        print("Domain has dot.")
    else: 
        print("Domain has no dot.") 

    #Task ten

Client_name = "  cBc News Team  "

clean_client_name = Client_name.strip().lower()
Upper_name = Client_name.strip().upper()

print(Client_name)
print(clean_client_name)
print(Upper_name)
print(clean_client_name[0:3])

#Task eleven

Client_name_3 = " PintEreSt"
contact_email = " pintrest.company@gmail.com   "
is_paid = True
clean_client_name3 = Client_name_3.strip().lower()
clean_client_email3 = contact_email.strip().lower()


if "@" in clean_client_email3:
    print(clean_client_name3)
    print(clean_client_email3)
    print(clean_client_email3[:clean_client_email3.find("@")])
    print(clean_client_email3[clean_client_email3.find("@"):])
    
    if is_paid:
        print("Paid account.")
    else: print("Unpaid account.")

else: print("cannot build contact card - invalid email.")

#Task twelve

text_three = "first.last@test.mail.com"

first_dot = text_three.find(".") 
rest_five = text_three[first_dot+1:]
second_dot = rest_five.find(".") + 1
full_second_dot = first_dot + second_dot
print(f"First dot index: {first_dot}")
print(f"Second dot index: {full_second_dot}")

#Task Thirteen

Text_four = "name [trial_user] active"
first_pos = Text_four.find("[")
sec_pos = Text_four.find("]")
print(Text_four[first_pos+1:sec_pos])

#Task fourteen
Messy_email = " JessIe.JaY@yahoo.com    "
clean_email4 = Messy_email.strip().lower()
has_at4 = "@" in clean_email4
if has_at4: 
    username4 = (clean_email4[:clean_email4.find("@")])
    domain4 = (clean_email4[clean_email4.find("@"):])
    print(username4)
    print(domain4)
    if "." in clean_email4:
        print("Username has dot.")
    if "." in domain4:
        print("Domain has dot")
    print(clean_email4.strip().upper())
else:
    print("Invalid email")






    

   




