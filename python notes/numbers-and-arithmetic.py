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