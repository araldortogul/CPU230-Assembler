#!/usr/bin/python3

# CMPE 230: Systems Programming Project 2 - CPU230 Executioner
# Author: Aral Dortogul, 2018402108

import sys

# The instruction codes (hex) of CPU230 commands.
instructions = {"HALT": 0x1, "NOP": 0xE, "LOAD": 0x2, "ADD": 0x4, "SUB": 0x5, "INC": 0x6, "DEC": 0x7, "XOR": 0x8, "AND": 0x9, "OR": 0xA, "NOT": 0xB, "CMP": 0x11, "PRINT": 0x1C, "STORE": 0x3, "READ": 0x1B, "SHL": 0xC, "SHR": 0xD, "PUSH": 0xF, "POP": 0x10, "JMP": 0x12, "JZ": 0x13, "JNZ": 0x14, "JC": 0x15, "JNC": 0x16, "JA": 0x17, "JAE": 0x18, "JB": 0x19, "JBE": 0x1A}
# Registers: 0x0000: PC, 0x0001: A, 0x0002: B, 0x0003: C, 0x0004: D, 0x0005: E, 0x0006: S
registers = {format(0x0000, "016b"): "0" * 16, format(0x0001, "016b"): "0" * 16, format(0x0002, "016b"): "0" * 16, format(0x0003, "016b"): "0" * 16, format(0x0004, "016b"): "0" * 16, format(0x0005, "016b"): "0" * 16, format(0x0006, "016b"): format(0xFFFE, "016b")}
# Zero, carry and sign flags (all boolean)
flags = {"ZF": False, "CF": False, "SF": False}
# The memory
memory = list()
for i in range(2**16):
	memory.append("0" * 8)

# Lines of the .bin file (list)
lines = list()
# Boolean variables
not_terminated = True # False only when a HALT instruction is encountered.
found_error = False # True when a syntax/semantics error is encountered.
# The output lines (list)
outputlines = list()

## == FUNCTIONS == ##

# Executes LOAD instruction.
def execute_load(addressMode, operand):
	if addressMode == "00": # Operand is an immediate data
		registers["0"*15 + "1"] = operand

	elif addressMode == "01": # Operand is a register
		if operand not in registers:
			found_error = True
			return
		registers["0"*15 + "1"] = registers[operand]

	elif addressMode == "10": # Operand is a memory address in a register
		if operand not in registers:
			found_error = True
			return

		address = int(registers[operand], 2)
		registers["0"*15 + "1"] = (memory[address] + memory[address + 1] if address != 0xFFFF else memory[address]) # Load 2 bytes

	elif addressMode == "11": # Operand is a memory address
		registers["0"*15 + "1"] = (memory[int(operand, 2)] + memory[int(operand, 2) + 1] if operand != 0xFFFF else memory[int(operand, 2)])
	else:
		found_error = True
		return

# Executes STORE instruction.
def execute_store(addressMode, operand):
	if addressMode == "01": # Operand is a register
		if operand not in registers:
			found_error = True
			return
		registers[operand] = registers["0"*15 + "1"]

	elif addressMode == "10": # Operand is a memory address in a register
		if operand not in registers:
			found_error = True
			return
		address = int(registers[operand], 2)
		memory[address] = registers["0"*15 + "1"][:8]
		if address != 0xFFFF:
			memory[address + 1] = registers["0"*15 + "1"][8:]

	elif addressMode == "11": # A memory address
		memory[int(operand, 2)] = registers["0"*15 + "1"][:8]
		if address != 0xFFFF:
			memory[int(operand, 2) + 1] = registers["0"*15 + "1"][8:]

	else:
		found_error = True
		return

# Performs addition of the 2 16-bit binary strings (str1 and str2) and an integer (opt), sets the flags accordingly and returns the sum. opt's default value is 0.
def addition(str1, str2, opt = 0):
	result = int(str1, 2) + int(str2, 2) + opt
	flags["CF"] = True if result > 0xFFFF else False
	result = format(result, "016b")[-16:]
	flags["ZF"] = True if result == "0" * 16 else False
	flags["SF"] = True if result[0] == "1" else False
	return result

# Takes the complement of the bits of the 16-bit binary string and returns the result.
def negate(str1):
	result = ""
	for ch in str1:
		if ch == "0":
			result += "1"
		elif ch == "1":
			result += "0"
		else:
			found_error = True
			return
	return result

# Returns the 16-bit binary string with the given address mode and operand.
def getNumber(addressMode, operand):
	num = None
	address = None
	if addressMode == "00":
		num = operand
	elif addressMode == "01":
		if operand not in registers:
			return
		num = registers[operand]
	elif addressMode == "10":
		if operand not in registers:
			return
		address = int(registers[operand], 2)
		num = memory[address] + memory[address + 1] # TODO: 0xFFFF check
	elif addressMode == "11":
		num = memory[int(operand, 2)] + memory[int(operand, 2) + 1] # TODO: 0xFFFF check
	else:
		return
	return [num, address]

# Executes ADD, SUB, CMP instructions.
def execute_add_sub_cmp(instr, addressMode, operand):
	num_and_address = getNumber(addressMode, operand)
	if num_and_address == None:
		found_error = True
		return
	num2 = num_and_address[0]

	if instr == instructions["ADD"]:
		registers["0"*15 + "1"] = addition(registers["0"*15 + "1"], num2)
	elif instr == instructions["SUB"]:
		registers["0"*15 + "1"] = addition(registers["0"*15 + "1"], negate(num2), 1)
	else: # CMP
		addition(registers["0"*15 + "1"], negate(num2), 1)

# Executes INC, DEC instructions.
def execute_inc_dec(instr, addressMode, operand):
	num_and_address = getNumber(addressMode, operand)
	if num_and_address == None:
		found_error = True
		return
	num1 = num_and_address[0]
	address = num_and_address[1]

	num2 = "0"*15 + "1"  if (instr == instructions["INC"]) else "1" * 16
	result = addition(num1, num2)

	if addressMode == "01":
		registers[operand] = result
	elif addressMode == "10":
		memory[int(address, 2)] = result[:8]
		memory[int(address, 2) + 1] = result[8:]
	elif addressMode == "11":
		memory[int(operand, 2)] = result[:8]
		memory[int(operand, 2) + 1] = result[8:]

# Executes the logical instructions XOR, AND, OR, NOT.
def execute_xor_and_or_not(instr, addressMode, operand):
	num_and_address = getNumber(addressMode, operand)
	if num_and_address == None:
		found_error = True
		return
	num2 = num_and_address[0]
	address = num_and_address[0]

	if instr == instructions["AND"]:
		result = format(int(registers["0"*15 + "1"], 2) & int(num2, 2), "016b")
	elif instr == instructions["OR"]:
		result = format(int(registers["0"*15 + "1"], 2) | int(num2, 2), "016b")
	elif instr == instructions["XOR"]:
		result = format(int(registers["0"*15 + "1"], 2) ^ int(num2, 2), "016b")
	elif instr == instructions["NOT"]:
		result = format(negate(num2), "016b")

	flags["SF"] == True if result[0] == "1" else False
	flags["ZF"] == True if result == "0" * 16 else False

	if instr != instructions["NOT"]:
		registers["0"*15 + "1"] = result
	else:
		if addressMode == "01":
			registers[operand] = result
		elif addressMode == "10":
			memory[int(address, 2)] = result[:8]
			memory[int(address, 2) + 1] = result[8:]
		elif addressMode == "11":
			memory[int(operand, 2)] = result[:8]
			memory[int(operand, 2) + 1] = result[8:]

# Executes the bit shifting instructions SHR, SHL.
def execute_shr_shl(instr, addressMode, operand):
	if addressMode != "01" or operand not in registers:
		found_error = True
		return
	num = registers[operand]
	if instr == instructions["SHR"]:
		registers[operand] = "0" + num[:-1]
	else: # SHL
		registers[operand] = num[1:] + "0"
		flags["CF"] = True if num[0] == "1" else False
	flags["SF"] == True if registers[operand][0] == "1" else False
	flags["ZF"] == True if registers[operand] == "0" * 16 else False

# Executes the stack operations PUSH, POP.
def execute_push_pop(instr, addressMode, operand):
	if addressMode != "01" or operand not in registers:
		found_error = True
		return
	S = int(registers[format(0x0006, "016b")], 2)
	if instr == instructions["PUSH"]:
		if S == -2:
			found_error = True # Stack overflow!
			return
		memory[S] = registers[operand][:8]
		memory[S + 1] = registers[operand][8:]
		registers[format(0x0006, "016b")] = format(S - 2, "016b")
	elif registers[format(0x0006, "016b")] == format(0xFFFE, "016b"):
		found_error = True # Stack underflow!
		return
	else: # POP
		registers[format(0x0006, "016b")] = format(S + 2, "016b")
		registers[operand] = memory[S + 2] + memory[S + 3]

# Executes READ statement.
def execute_read(addressMode, operand):
	#Input = sys.stdin.read(1)
	Input = input()
	character = format(ord(Input[0]), "016b")
	if addressMode == "01": # Reads from register.
		registers[operand] = character
	elif addressMode == "10": # Reads from memory address in register.
		if operand not in registers:
			found_error = True
			return
		address = int(registers[operand], 2)
		memory[address] = character[:8]
		memory[address + 1] = character[8:]
	elif addressMode == "11": # Reads from memory address.
		memory[int(operand, 2)] = character[:8]
		memory[int(operand, 2) + 1] = character[8:]
	else:
		found_error = True

# Executes PRINT statement.
def execute_print(addressMode, operand):
	if addressMode == "00": # Prints immediate data.
		outputlines.append(chr(int(operand, 2)))
	elif addressMode == "01": # Prints register.
		outputlines.append(chr(int(registers[operand], 2)))
	elif addressMode == "10": # Prints data in memory address in register.
		if operand not in registers:
			found_error = True
			return
		address = int(registers[operand], 2)
		character = chr(int(memory[address] + memory[address + 1], 2))
		outputlines.append(character)
	elif addressMode == "11": # Prints data in memory address.
		character = chr(int(memory[int(operand, 2)] + memory[int(operand, 2) + 1], 2))
		outputlines.append(character)
	else:
		found_error = True

# Executes the jump statements JMP, JZ/JE, JNZ/JNE, JC, JNC, JA, JAE, JB, JBE.
def execute_jump(instr, addressMode, newPC):
	if addressMode != "00":
		found_error = True
		return False
	if instr == instructions["JMP"] or (instr == instructions["JZ"] and flags["ZF"]) or (instr == instructions["JNZ"] and not flags["ZF"]) or (instr == instructions["JC"] and flags["CF"]) or (instr == instructions["JNC"] and not flags["CF"]) or (instr == instructions["JA"] and not flags["SF"]) or (instr == instructions["JAE"] and (not(flags["SF"]) or flags["ZF"])) or (instr == instructions["JB"] and flags["SF"]) or (instr == instructions["JBE"] and (flags["SF"] or flags["ZF"])):
		registers["0"*16] = newPC
	else:
		registers["0"*16] = format(int(registers["0"*16], 2) + 3, "016b")
	return True

## == EXECUTION == ##

f = open(sys.argv[1], "r")

# Reading the .bin file line by line and sectioning the bytes into 3 parts: instruction, addressing mode and operand
for line in f:
	if line == "Error!":
		found_error = True
		break
	bline = format(int(line, 16), "024b")
	lines.append({"instr": bline[0:6], "addrMode": bline[6:8], "operand": bline[8:24]})

# Executing the lines in the .bin file
while not found_error:
	if (int(registers["0"*16], 2) // 3) >= len(lines):
		found_error = True
		break
	line = lines[int(registers["0"*16], 2) // 3]
	instruction = int(line["instr"], 2)
	if instructions["JMP"] <= instruction and instruction <= instructions["JBE"]: # The instruction is any jumping instruction
		if execute_jump(instruction, line["addrMode"], line["operand"]):
			continue
	elif instruction == instructions["LOAD"]: # The instruction is LOAD
		execute_load(line["addrMode"], line["operand"])
	elif instruction == instructions["STORE"]: # The instruction is STORE
		execute_store(line["addrMode"], line["operand"])
	elif (instruction == instructions["ADD"]) or (instruction == instructions["SUB"]) or (instruction == instructions["CMP"]): # The instruction is ADD, SUB, or CMP
		execute_add_sub_cmp(instruction, line["addrMode"], line["operand"])
	elif (instruction == instructions["INC"] or instruction == instructions["DEC"]): # The instruction is INC or DEC
		execute_inc_dec(instruction, line["addrMode"], line["operand"])
	elif (instructions["XOR"] <= instruction) and (instruction <= instructions["NOT"]): # The instruction is XOR, AND, OR or NOT
		execute_xor_and_or_not(instruction, line["addrMode"], line["operand"])
	elif (instruction == instructions["SHL"]) or (instruction == instructions["SHR"]): # The instruction is SHR or SHL
		execute_shr_shl(instruction, line["addrMode"], line["operand"])
	elif (instruction == instructions["POP"]) or (instruction == instructions["PUSH"]): # The instruction is PUSH or POP
		execute_push_pop(instruction, line["addrMode"], line["operand"])
	elif instruction == instructions["READ"]: # The instruction is READ
		execute_read(line["addrMode"], line["operand"])
	elif instruction == instructions["PRINT"]: # The instruction is PRINT
		execute_print(line["addrMode"], line["operand"])
	elif instruction == instructions["HALT"]: # The instruction is HALT
		break
	elif instruction != instructions["NOP"]: # The instruction !! ISN'T !! "NOP", i.e. the instruction is not defined.
		found_error = True
		break

	if (int(registers["0"*16], 2) // 3) < len(lines): # Update PC
		registers["0"*16] = format(int(registers["0"*16], 2) + 3, "016b")
	else:
		found_error = True

# Output file generation
outFile = open(sys.argv[1][:-4] + ".txt", "w")
if found_error:
	outFile.write("Error!")
else:
	for o in outputlines:
		outFile.write(o + "\n")
