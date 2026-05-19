sentence = "I like Apples"
word = "appLe"
print(word[3])
print(word.lower() in sentence.lower())




if False:
    email = "fghjkl@hh"
    is_valid = "@" in email
    print(is_valid)

    '''
    Write a small script that:
    stores an email
    cleans it with .strip().lower()
    checks whether it contains @
    if it does, prints:
    cleaned email
    username
    domain
    otherwise prints:
    "invalid email"
    '''
    print("*Task 1*")
    email = " dom22@gmail.com  "
    clean_email = email.strip().lower()
    at_pos = clean_email.find("@")
    username = clean_email[:at_pos]
    domain = clean_email[at_pos + 1:]
    if "@" in email:
        print("clean email: ", clean_email)
        print("username:", username)
        print("domain:", domain)
    else:
        print("invalid email")
    '''
    Store:
    company name
    email
    is_paid
    Clean the email first.
    Then print:
    one summary sentence with the company and email
    a second line that says:
    "paid account" if is_paid is True
    "trial account" otherwise
    '''
    print("*Task 2*")

    company_name = "didenko fam"
    email = " didenko.fam@gmail.com "
    is_paid = True

    clean_email = email.strip().lower()
    print(f"Company: {company_name} email: {clean_email}")

    if is_paid == True:
        print("paid accont")
    else:
        print("trial account")

    '''
    Task 3 — Username formatting
    Store:
    email = "  dOMinikA@School.org  "

    Clean the email.
    If it contains @:
    extract the username
    print it with:
    first letter uppercase
    rest lowercase
    If not, print "invalid email".
    '''
    print("Task 3")

    email = "  dOMinikA@School.org  "
    clean_email = email.strip().lower()

    if "@" in clean_email:
        at_pos = clean_email.find("@")
        username = clean_email[:at_pos]
        username_big = username.capitalize()
        print(username_big)
    else:
        print("invalid email")

    '''
    Task 4 — Find the second space
    Store:
    text = "Big Blue Company"

    Find:
    the first space
    the second space
    Then print:
    the position of the first space
    the position of the second space
    the word between them

    '''
    print("task 4")

    text = "Big Blue Company"

    first_space = text.find(" ")
    print(first_space)

    rest = text[first_space + 1:]

    second_space_in_rest = rest.find(" ")
    print(second_space_in_rest)

    second_space = first_space + 1 + second_space_in_rest
    print(second_space)

    print(text[first_space +1:second_space])

    '''
    Task 5 — Print the middle word
    Store:
    text = "Green Apple Juice"

    Find the first and second spaces.
    Then print only:
    Apple

    Use helper variables. Do not try to do everything in one line.

    '''
    print("Task 5")

    text = "Green Apple Juice"
    first_space = text.find(" ")
    rest = text[first_space +1:]
    second_space_in_rest = rest.find(" ")
    second_space = first_space +1+ second_space_in_rest
    print(text[first_space +1: second_space])

    '''
    Task 6 — First and last name from username
    Store:
    email = "first.last@gmail.com"

    Clean it if needed.
    If it contains @:
    extract the username
    find the dot in the username
    print:
    first name part
    last name part
    If the username has no dot, print:
    "username has no dot"
    '''
    print("-----Task 6")

    email = "first.lastgmail.com"
    if "@" in email:
        at_pos = email.find("@")
        username6 = email[:at_pos]
        print(username6)
        
        if "." in username6:
            dot_pos = username6.find(".")
            first_name = username6[:dot_pos]
            last_name = username6[dot_pos + 1:]
            
            print(dot_pos)
            print(first_name)
            print(last_name)
        else:       
            print("username6 has no dot")
    else:
        print("username6 has no @")
        
    '''Task 7 — Domain puzzle
    Store:
    email = "student@test.ca"

    If it contains @:
    extract the domain
    find the dot in the domain
    print:
    the part before the dot
    the part after the dot
    Example result:
    test
    ca'''

    print("Task 7")

    email = "student@test.ca"

    if "@" in email:
        at_pos = email.find("@")
        domain = email[at_pos+1:]
        dot_pos = domain.find(".")

        before_dot = domain[:dot_pos]
        print(before_dot)

        after_dot = domain[dot_pos+1:]
        print(after_dot)
    '''
    Task 8 — Check for a second @
    Store:
    email = "user@@gmail.com"

    Find the first @.
    Then search again in the text after the first @.
    Print:
    "has second @" if another @ is found
    "only one @" otherwise
    This is a puzzle task. Use more than one helper variable.'''

    print("Task 8")

    email = "user@@gmail.com"

    first_at_pos = email.find("@")
    rest = email[first_at_pos+1:]
    second_at_pos = rest.find("@")

    if second_at_pos != -1:
        print("has second @")

    else: 
        print("only one @")

    '''
    Task 9 — Check username and domain separately
    Store:
    email = "first.last@yahoo.com"

    If the email contains @:
    extract username
    extract domain
    check if the username contains .
    check if the domain contains .
    print clear messages for both
    '''
    email = "first.last@yahoo.com"

    at_pos = email.find("@")

    username = email[:at_pos]
    domain = email[at_pos+1:]

    if "." in username:
        print("username has '.'")

    if "." in domain:
        print("domain has '.'")

    '''
    Task 10 — Client name cleaner
    Store:
    client_name = "  cBc News Team  "

    Create:
    clean_name using .strip().lower()
    upper_name using .strip().upper()
    Then print:
    original value
    cleaned lowercase value
    cleaned uppercase value
    first 3 characters of the cleaned value
    '''

    print("Task 10")


    client_name = "  cBc News Team  "

    clean_name = client_name.strip().lower()
    upper_name = client_name.strip().upper()

    print(client_name)
    print(clean_name)
    print(upper_name)

    print(clean_name[:3])

    '''Task 11 — Mini contact card
    Store:
    client name
    contact email
    is_paid
    Clean the email and client name.
    If the email contains @, print a small contact card like:
    client
    email
    username
    domain
    account type
    If the email does not contain @, print:
    "cannot build contact card — invalid email"
    '''

    print("Task 11")

    client_name = " DoMi "
    client_email = "  dOmi@Gmail.COM  "
    is_paid = False

    clean_name = client_name.strip().lower()
    clean_email = client_email.strip().lower()

    at_pos = clean_email.find("@")

    if "@" in clean_email:
        print("client contact card")
        print(clean_name)
        print(clean_email)
        print(clean_email[:at_pos])
        print(clean_email[at_pos+1:])

        if is_paid:
            print("account type is paid")
        else:
            print("trial account")

    else:
        print("cannot build contact card — invalid email")

    '''Task 12 — Second dot challenge
    Store:
    text = "first.last@test.mail.com"

    Find:
    the first dot
    then the second dot after that
    Print:
    the position of the first dot
    the position of the second dot
    Optional: also print the text between the first and second dots.
    Use small steps and helper variables.
    '''
    print("Task 12")

    text = "first.last@test.mail.com"

    first_dot = text.find(".")

    rest = text[first_dot+1:]

    second_dot = rest.find(".")

    print(first_dot)

    actual_second_dot = first_dot+1+second_dot
    print(actual_second_dot)

    in_between_words = text[first_dot+1:actual_second_dot]
    print(in_between_words)

    '''Task 13 — Text between two symbols
    Store:
    text = 

    Find:
    the position of [
    the position of ]
    Then print only the text between them:
    trial_user
    '''
    print("Task 13")

    text = "name [trial_user] active"

    bracet_pos_1 = text.find("[")
    print(bracet_pos_1)

    rest = text[bracet_pos_1+1:]
    print(rest)

    bracet_pos_2 = rest.find("]")
    print(bracet_pos_2)

    actual_bracet_pos_2 = bracet_pos_1 +1+ bracet_pos_2
    print(actual_bracet_pos_2)

    text_between_bracets = text[bracet_pos_1+1:actual_bracet_pos_2]
    print(text_between_bracets)

    '''Task 14 — Email inspector mini-project
    Write a slightly bigger script that:
    stores a messy email
    cleans it
    checks whether it has @
    if valid:
    prints username
    prints domain
    prints whether username has a dot
    prints whether domain has a dot
    prints the email in uppercase
    if invalid:
    prints "invalid email"
    '''
    print("Task 14")

    email = "  doMI@gMail.cOm   "
    clean_email = email.strip().lower()

    at_pos = clean_email.find("@")
    dot_pos = clean_email.find(".")

    if "@" in clean_email:
        username = clean_email[:at_pos]
        domain = clean_email[at_pos+1:]
        print(username)
        print(domain)
        
        if "." in username:
            print("username has dot")
        
        else:
            print("no dot in username")
        
        if "." in domain:
            print("domain has dot")
        
        else:
            print("no dot in domain")
        
        clean_email_upper = clean_email.upper()
        print(clean_email_upper)

    else:
        print("invalid email")
