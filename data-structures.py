print(f'\n\tData Structures')
print(f'\t------------------------\n')


#**List:** Start with `nums = [3, 1, 4, 1, 5]`.
#Append 9, remove the first 1, sort, and print the count of 1’s.

nums = [3, 1, 4, 1, 5]
nums.append(9)
nums.remove(1)
nums.sort()
print(nums.count(1))

#Tuple: Given a coordinate tuple (x, y, z), unpack it and print each value.

coordinates = (4234, 151, -563)
#unpacking = extracting values back into variables

(x, y, z) = coordinates
print(x, y, z)

#Set: From a list with duplicates, build a set and show its length difference.
s = {3,1,2,5,8,1,3,5}
l = [3,1,2,5,8,1,3,5]
print(s, l)
print(len(s), len(l))
#a set does not have duplicates while a list can

#Dict: Build a phonebook dict mapping names to numbers; then let the user look up by name.

phonebook = {
    'Bob':123, 
    'Jim':321,
    'Phil':456,
    'Saul':654
}
while True:
    lookup = input(f'Who you calling?\n')
    try:
        person = phonebook[lookup]
        print(person)
        break
    except KeyError:
        print(f'Person not found, please try again...\n')
