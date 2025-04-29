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


print(f'\n\tNumbers & Arithmetic')
print(f'\t------------------------\n')

# Write a function is_even(n) that returns True if n is even, else False.
def is_even(n):
    if n % 2 == 0:
        print(f'Even Number\n')
        return True
    else:
        print(f'Odd Number\n')
        return False
n=2
#n = int(input('Enter a number: '))
is_even(n)

# Compute the factorial of an integer using a for loop and the * operator.
# Factorial: multiply all whole numbers from our chosen number down to 1
# 4! = 4 × 3 × 2 × 1 = 24.

n = 4 #find factorial of 4
x = 1 #we need to store n in another variable outside the for loop so that n+1 in range() doesn't change
for i in range(1, n+1): #(1, n+1) - i starts at 1 and ends at n+1 wwhich is 4
    x *= i #multiples n by i and stores it in n
    #following iterations will store n in results
print(x) 

n = 5
x = 1
for i in range(1, n+1):
    x *= i
print(x)

print(f'\n\tBooleans & Operators')
print(f'\t------------------------\n')

#Prompt the user for two numbers and print whether they are equal,
#and whether the first is greater than the second.

def equal_check():
    while True:
        try:
            Num1 = int(input('Enter 1st number: '))
            if int(Num1) < 0:
                print(f'Please enter a valid whole number.')
                Num1 = input(f'Enter 1st number: ')
            else:
                break
        except (ValueError, TypeError):
            print(f'Please enter a valid whole number.')

    while True:
        try:
            Num2 = int(input('Enter 2nd number: '))
            if int(Num2) < 0:
                print(f'Please enter a valid whole number.')
                Num2 = input(f'Enter 2nd number: ')
            else:
                break
        except (ValueError, TypeError):
            print(f'Please enter a valid whole number.')

    if Num1 == Num2:
        print(f'These 2 numbers are equal.')
    elif Num1 > Num2:
        print(f'The 1st number is greater than the 2nd number.')
    elif Num1 < Num2:
        print(f'The 1st number is less than the 2nd number.')
    else:
        return 1
    
equal_check()

#Given three Boolean flags (`a`, `b`, `c`), print “OK” only if exactly two are `True`.

a = True
b = True
c = True

flags = (a,b,c)
if sum(flags) == 2: # True=1 and False=0; treating it as numbers allows us to do this
    print(f'\nOK')
else:
    print(f'\nNOT OK')

#Write a snippet that, given three Boolean variables a, b, and c,
#prints exactly one of the following based on how many are True:
# "All True" "None True" "One True" "Two True"

if sum(flags) == 1:
    print(f'\nOne True')
elif sum(flags) == 2:
    print(f'\nTwo True')
elif sum(flags) == 3:
    print(f'\nTwo True')
else:
    print(f'\nAll True')

if all(flags): print(f'\nSAME') #all() checks if every element in an iterable is True
else: print(f'\nDIFFERENT')

if False not in flags: print(f'\nSAME') #this is a membership check
else: print(f'\nDIFFERENT') 

#using a manual loop
all_true = True
for i in flags:
    if i == True:
        continue
    else:
        all_true = False
        break
print(f'\nSAME' if all_true == True else '\nDIFFERENT')


print(f'\n\tString Formatting & Escape Characters')
print(f'\t------------------------\n')

# test commit