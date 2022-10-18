!/usr/bin/env python3

from pwn import *
import sys

host, port = '192.168.159.168', 1337

s = remote(host, port, level='error')

operators = { 
        '+': lambda x,y: x+y,
        '-': lambda x,y: x-y,
        '*': lambda x,y: x*y,
        '/': lambda x,y: x/y 
}
 
def substringExpression(msg):
        msg = msg.decode()
        msg = msg.replace('(','')
        msg = msg.replace(')','')
        msg = msg.replace("'","")
        msg = msg.split(', ')
        return msg

def evaluateExpression(num1, op, num2):
        num1, num2 = int(num1), int(num2)
        return int(operators[op](num1, num2))


msg = s.recvuntil('> ')

while b'(' in msg and b')' in msg:   
        problem = substringExpression(msg[-14:-3])
        solution = str(evaluateExpression(problem[0], problem[1], problem[2]))
        s.sendline(solution.encode())

        print(ctr, ') ', (' '.join(problem)), ' = ', solution)

        try:
                msg = s.recvuntil('> ')
        except:
                print("All solved!\n")
                break

msg = s.recv()
print(msg)
