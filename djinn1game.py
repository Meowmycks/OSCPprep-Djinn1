#!/usr/bin/env python3

from pwn import *
import sys

host, port = '192.168.159.168', 1337

s = remote(host, port, level='error')

msg = s.recvuntil('> ')
#print(msg[430:441])

problem = msg[430:441]
problem = problem.decode()
problem = problem.replace('(','')
problem = problem.replace(')','')
problem = problem.replace("'","")
problem = problem.split(', ')
#print(problem)

operators = {
	'+': lambda x,y: x+y,
	'-': lambda x,y: x-y,
	'*': lambda x,y: x*y,
	'/': lambda x,y: x/y
}

def evaluateExpression(num1, op, num2):
	num1, num2 = int(num1), int(num2)
	return int(operators[op](num1, num2))

#print(problem)
#print(evaluateExpression(problem[0], problem[1], problem[2]))

solution = str(evaluateExpression(problem[0], problem[1], problem[2]))
s.sendline(solution)

msg = s.recvuntil('> ')
ctr = 1
while b'(' in msg and b')' in msg:
	problem = msg[:-3]
	problem = problem.decode()
	problem = problem.replace('(','')
	problem = problem.replace(')','')
	problem = problem.replace("'","")
	problem = problem.split(', ')

	solution = str(evaluateExpression(problem[0], problem[1], problem[2]))
	s.sendline(solution.encode())
	print(ctr,') ',(' '.join(problem)),' = ',solution)
	ctr = ctr + 1

	try:
		msg = s.recvuntil('> ')
	except:
		print("All solved!")
		break
print()
msg = s.recv()
print(msg)
