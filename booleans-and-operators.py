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