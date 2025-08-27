# C

### **Vocab**

**Casting/Cast** - Telling the compiler to treat a value as another specified types

- syntax = `(type) value`
    - `(type)` = the type you want to convert to
    - `value` = the variable or expression you want to convert

**Dereferencing** - Accessing the value of a memory address held by a pointer.

### Why do we need pointers?

1. Allows a function to change value of a variable outside
    1. A copy is made of data passed to a function
    2. Passing a pointer allows for modifications to the original variable
2. For dynamic memory allocation with `malloc`
3. Large structures or arrays can be passed via pointers instead of copying the whole data.
4. Data structures like linked lists, trees, graphs rely on pointers to connect elements.

### Asterisk (*)

- Declaring a pointer
- Dereferencing a pointer

Example:

```c
int *arr;
int n;
scanf("%d", &n);            
arr = (int*) malloc(n * sizeof(int));
for(int i=0; i<n; i++) {
    arr[i] = i*2;  
}
```

Line 1: 

- Declares a pointer. This pointer points to an integer value

Line 3:

- Takes user input and stores it in `n`
- *You must use the ‘&’ operator for most variable types (except for arrays/strings).*

Line 4: 

- Allocates memory for `n` integers.
- The size of 1 int is usually 4 bytes; so 4 ints = 16 bytes
- malloc() returns the address of the beginning of the block of memory it just allocated
    - returned as void pointer (void*) so we cast it to (int*) to be treated as an integer pointer
- now arr = int* (converted from void*)

Line 5/6: 

- Stores 0 in`i` variable. For loop keeps going until `i` < n. Increments `i` by 1 each loop.
- `arr[i]` = `*(arr + i)`
- This dereferences `*(arr + i)` to access the value at the memory address the pointer is referencing
    - Remember: malloc() returns a memory address that is the beginning of what it dynamically allocated
    - so arr = address of the first block of allocated memory
- the `+i` in the `[i]` moves `arr` by `i` position
    - essentially each loop will start at the memory address of the following `n`
    - then stores whatever value i times 2 is at that memory address

Example: n =3

```c
Step i=0: arr[0] = 0*2 = 0
Memory Address -> Value: 1000 -> 0   1004 -> ?   1008 -> ?

Step i=1: arr[1] = 1*2 = 2
Memory Address -> Value: 1000 -> 0   1004 -> 2   1008 -> ?

Step i=2: arr[2] = 2*2 = 4
Memory Address -> Value: 1000 -> 0   1004 -> 2   1008 -> 4
```

Clarification on `i`:

- C will automatically multiplies `i` by the size of the type *arr points to.
- `arr` points to `int`, which is 4 bytes on most systems.
- So `arr + 1` → 1000 + 4 = 1004
- `arr + 2` → 1000 + 8 = 1008
- arr[] allows access to arr* like an array, with each `n` ’s memory address in this code treated as an array element
- Each `i` corresponds to a memory offset from the start of the block: