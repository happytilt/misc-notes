print(f'\n\tData and Variables Type')
print(f'\t------------------------\n')

# Create variables for your name (str),
# age (int), GPA (float), and student status (bool).
# Print each with its type.

name = 'Huy'
age = 20
gpa = 3.5
studentStatus = True

print(f'Name = {name}\nAge = {age}\nGPA = {gpa}\nStudent Status = {studentStatus}\n')
print(f'Name Variable is {type(name)} and name length is {len(name)}\n')

# Assign None to a variable and then test if var is None: to print a message.

print(f'declaring gpa to None')
gpa = None
if gpa == None:
    print(f'no GPA found')
