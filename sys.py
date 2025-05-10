import sys
import time

print(sys.version)
print(sys.executable)
print(sys.platform)

#iterates over each line of user input
for input in sys.stdin:
    #input.strip() strips all leading, trailing whitespace and new line characters
    #if the stripped line form user input is 'exit', break the for loop
    if input.strip() == 'exit':
        break

    #write to standard output (the console)
    #writes '>>' 
    #{} is a placeholder for the format() function which writes input to it
    sys.stdout.write('>> {}'.format(input))

#when writing, data sits in buffer until the loop ends
for i in range(5):
    sys.stdout.write(f'{i}')
    sys.stdout.flush()  #pushes i from buffer into output immediately instead of waiting for loop to finish
    time.sleep(1)

for progress in range(0,51):
    time.sleep(0.1)
    sys.stdout.write('{}\\50 \r'.format(progress))
    sys.stdout.flush()
print()

