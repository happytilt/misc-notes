import sys

if len(sys.argv) < 2:
    print('Supply a username and password...')
    sys.exit(1)

#sys.argv[0] is always the script name
username = sys.argv[0]
password = sys.argv[1]

print(sys.argv[0])
print(sys.argv[1])
print(sys.argv[2])

print(sys.path)
print(sys.modules)

sys.exit(0)