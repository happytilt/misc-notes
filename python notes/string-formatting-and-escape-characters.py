print(f'\n\tString Formatting & Escape Characters')
print(f'\t------------------------\n')

# Ask the user for first and last name, then greet them with an f-string.

fname = input(f'What is your first name: ')
lname = input(f'What is your last name: ')

print(f'hello {fname} {lname}!\n')

#Create a multiline string that includes quotes and backslashes, using appropriate escape sequences

print(f'this is a quotation mark \' and this is a back slash \\\n')


'''
Recreate the following output

===== Shopping Receipt =====

Item       	    Price
----------------------------
Milk       	    $2.50
Bread      	    $3.00
Eggs       	    $4.25

----------------------------
Subtotal   	    $9.75
Tax (8%)   	    $0.78
Total      	    $10.53

Thank you for shopping with us!
'''

d = {
    'Milk' : '1.99',
    'Bread' : '3.99',
    'Eggs' : '4.99'
}

print('===== Shopping Receipt =====')

print(f'Item\t\tPrice')
print('----------------------------')
print(f'Milk\t\t${d.get('Milk')}')
print(f'Bread\t\t${d.get('Bread')}')
print(f'Eggs\t\t${d.get('Eggs')}\n')
print('----------------------------')
subtotal = sum(float(i) for i in d.values())
#Loop that takes all values of the dictionary and adds them all up
#d.values() prints out strings and numbers, which cant be summed
#float(i) converts i to a float before sum()'d up
print(f'Subtotal\t${subtotal}')
tax = sum(float(i) for i in d.values()) * 0.08
print(f'Tax (8%)\t${tax:.2f}')
# :.2f makes the float var show 2 decimal 
total = subtotal + tax
print(f'Total\t\t${total:.2f}')
print(f'\nThank you for shopping with us!\n')