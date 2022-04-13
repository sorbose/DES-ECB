# DES-ECB
Data Encryption Standard (DES) ECB Mode based on C++ bitset

(for education only)
Input and output like this:
```
Data Encryption Standard (DES) ECB Mode (zero padding) 
(Designed for network security course homework)        
Do you want to encrypt or decrypt?
  [E]ncrypt (default)
  [D]ecrypt
E
Plaintext to be encrypted (in one line) : 
hello world
Select the type of PLAINTEXT you enter:
  [S]tring (default)
  [H]ex
s

The length of the plaintext you typed in: 11
Key for encryption:
1234567890abcdef
Select the type of KEY you enter:
  [S]tring (default)
  [H]ex
h
The length of the key you typed in: 16

After initial permutation:
df40ded200ff9dd0
0701060000070201

block [0]
df40ded200ff9dd0


  round [1]
  left:
00000000
11111111
10011101
11010000
  right:
00111011
01011011
00110010
11011110

......

Swap left and right:
57cfe68fe4fabf53

after IP^-1:
5b7fdd396aacf6bd

Encryption result (hex):
5b7fdd396aacf6bd
c19c253125329482

The plaintext you typed in (hex):
68656c6c6f20776f
726c640000000000
```
