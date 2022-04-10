#!/usr/bin/python3

# CMPE 230: Systems Programming Project 2 - CPU230 Assembler
# Author: Aral Dortogul, 2018402108
import sys, re

# === CPU230 Instruction Dictionaries === # (Grouped by their operand types.)
# Instructions that take no operand:
instruction_with_no_operand = {"HALT": 0x1, "NOP": 0xE}
# Instructions that can take an operand of the following types: immediate data, memory, register:
instruction_with_IMR_operand = {"LOAD": 0x2, "ADD": 0x4, "SUB": 0x5, "INC": 0x6, "DEC": 0x7, "XOR": 0x8, "AND": 0x9, "OR": 0xA, "NOT": 0xB, "CMP": 0x11, "PRINT": 0x1C}
# Instructions that can take an operand of the following types: memory, register:
instruction_with_MR_operand = {"STORE": 0x3, "READ": 0x1B}
# Instructions that can take only a register as an operand:
instruction_with_R_operand = {"SHL": 0xC, "SHR": 0xD, "PUSH": 0xF, "POP": 0x10}
# Instructions that can take only immediate data as an operand:
instruction_with_I_operand = {"JMP": 0x12, "JZ": 0x13, "JE": 0x13, "JNZ": 0x14, "JNE": 0x14, "JC": 0x15, "JNC": 0x16, "JA": 0x17, "JAE": 0x18, "JB": 0x19, "JBE": 0x1A}
#Registers
registers = {"PC": 0X0000, "A": 0x0001, "B": 0x0002, "C": 0x0003, "D": 0x0004, "E": 0x0005, "S": 0x0006}

# Dictionary of labels
labels = dict()
# Hexadecimal, assembled code lines
hexCodes = list()
# True when a syntax error is encountered.
syntaxErrorFound = False
# Instructions are 6 bits
instrBytes = "06b"
# Operands are 16 bits (2 bytes)
opBytes = "016b"
# Hexadecimal codes are 6 digits.
hexCodeBytes = "06X"
# Dictionary of addressing modes.
addressingMode = {"immediate": "00", "register": "01", "memreg": "10", "memaddr": "11"}

## == FUNCTIONS == ##

# Calculates and returns the hexadecimal assembled code of an instruction that takes no operands.
def getHexCode_no_op(command):
	return format(int(format(instruction_with_no_operand[command], instrBytes) + ("0" * 18), 2), "06x")

# Calculates and returns the hexadecimal assembled code of an instruction that can take immediate data, register or memory as an operand.
def getHexCode_IMR_op(command, operand):
	if operand[0] == '[' and operand[-1] == ']': # Memory address
		address = operand[1:-1]

		if address in registers:
			bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["memreg"] + format(registers[address], opBytes)

		elif (len(address) <= 4 and re.search(r"\d[0-9A-Fa-f]{" + (str(len(address) - 1) if len(address) > 1 else "0") + "}", address)) or (len(address) <= 5 and re.search(r"0[A-Fa-f][0-9A-Fa-f]{" + (str(len(address) - 2) if len(address) > 2 else "0") + "}", address)):
			bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["memaddr"] + format(int(address, 16), opBytes)

		elif address.lower() in labels: # Memory address is a label name.
			bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["immediate"] + format(labels[address.lower()], opBytes)

		else:
			syntaxErrorFound = True
			return

	elif operand in registers: # Immediate data in register
		bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["register"] + format(registers[operand], opBytes)

	elif operand.lower() in labels: # Immediate data is a label name.
		bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["immediate"] + format(labels[operand.lower()], opBytes)

	elif (len(operand) <= 4 and re.search(r"\d[0-9A-Fa-f]{" + (str(len(operand) - 1) if len(operand) > 1 else "0") + "}", operand)) or (len(operand) <= 5 and re.search(r"0[A-Fa-f][0-9A-Fa-f]{" + (str(len(operand) - 2) if len(operand) > 2 else "0") + "}", operand)):
		#elif (len(operand) <= 4 and re.search("[0-9A-Fa-f]{" + len(operand) + "}", operand)) or (len(operand) <= 5 and re.search("0[0-9A-Fa-f]{" + len(operand) - 1 + "}", operand)): # Immediate data is a 4 byte hexadecimal number.
		bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["immediate"] + format(int(operand, 16), opBytes)
	elif len(operand) == 3 and operand[0] == r"'" and operand[-1] == r"'": # Immediate data is a char
		bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["immediate"] + format(ord(operand[1]), opBytes)
	else:
		syntaxErrorFound = True
		return

	return format(int(bcode, 2), hexCodeBytes)

# Calculates and returns the hexadecimal assembled code of an instruction that can take memory or register as an operand.
def getHexCode_MR_op(command, operand):
	if operand[0] == '[' and operand[-1] == ']': # Memory address
		address = operand[1:-1]
		if address in registers:
			bcode = format(instruction_with_MR_operand[command], instrBytes) + addressingMode["memreg"] + format(registers[address], opBytes)
		elif (len(address) <= 4 and re.search(r"\d[0-9A-Fa-f]{" + (str(len(address) - 1) if len(address) > 1 else "0") + "}", address)) or (len(address) <= 5 and re.search(r"0[A-Fa-f][0-9A-Fa-f]{" + (str(len(address) - 2) if len(address) > 2 else "0") + "}", address)):
			bcode = format(instruction_with_MR_operand[command], instrBytes) + addressingMode["memaddr"] + format(int(address, 16), opBytes)
		elif address.lower() in labels: # Memory address is a label name.
			bcode = format(instruction_with_IMR_operand[command], instrBytes) + addressingMode["immediate"] + format(labels[address.lower()], opBytes)
		else:
			syntaxErrorFound = True
			return

	elif operand in registers: # Immediate data in register
		bcode = format(instruction_with_MR_operand[command], instrBytes) + addressingMode["register"] + format(registers[operand], opBytes)
	else:
		syntaxErrorFound = True
		return
	return format(int(bcode, 2), hexCodeBytes)

# Calculates and returns the hexadecimal assembled code of an instruction that can take only immediate data as an operand.
def getHexCode_I_op(command, operand):

	if operand.lower() in labels: # Immediate data is a label name.
		bcode = format(instruction_with_I_operand[command], instrBytes) + addressingMode["immediate"] + format(labels[operand.lower()], opBytes)
	elif (len(operand) <= 4 and re.search(r"\d[0-9A-Fa-f]{" + (str(len(operand) - 1) if len(operand) > 1 else "0") + "}", operand)) or (len(operand) <= 5 and re.search(r"0[A-Fa-f][0-9A-Fa-f]{" + (str(len(operand) - 2) if len(operand) > 2 else "0") + "}", operand)):
		bcode = format(instruction_with_I_operand[command], instrBytes) + addressingMode["immediate"] + format(int(operand, 16), opBytes)
	elif len(operand) == 3 and operand[0] == r"'" and operand[-1] == r"'": # Immediate data is a char
		bcode = format(instruction_with_I_operand[command], instrBytes) + addressingMode["immediate"] + format(ord(operand[1]), opBytes)
	else:
		syntaxErrorFound = True
		return
	return format(int(bcode, 2), hexCodeBytes)

# Calculates and returns the hexadecimal assembled code of an instruction that can take only a register as an operand.
def getHexCode_R_op(command, operand):
	if operand in registers: # Immediate data in register
		bcode = format(instruction_with_R_operand[command], instrBytes) + addressingMode["register"] + format(registers[operand], opBytes)
	else:
		syntaxErrorFound = True
		return
	return format(int(bcode, 2), hexCodeBytes)

## == ASSEMBLING == ##

f = open(sys.argv[1], "r")

# The list of tokens
tokenizedlines = list()

# Counts the total number of bytes read so far.
byteCounter = 0
for line in f:
	line = line.strip()
	currenttokens = re.findall(r'\S+', line)
	# If the line is a label:
	if len(currenttokens) == 0:
		continue

	if len(currenttokens) == 1 and currenttokens[0][-1] == ':':
		if currenttokens[0][:-1].lower() in labels: # If the label is already defined.
			syntaxErrorFound = True
			break
		labels[currenttokens[0][:-1].lower()] = byteCounter # Add the label to the labels dictionary with its bytes.
		continue
	# If it is not a label:
	tokenizedlines.append(currenttokens) # Add the tokens list to tokenizedLines list
	byteCounter += 3

for tokens in tokenizedlines:
	if not tokens: # Empty list
		continue
	instruction = tokens[0]

	if instruction in instruction_with_no_operand: # If the instruction takes no operand
		if len(tokens) != 1: # If the token count of the line is not 1
			syntaxErrorFound = True
			break
		hexCodes.append(getHexCode_no_op(tokens[0]))
	elif len(tokens) != 2: # If the token count of the line is not 2
		syntaxErrorFound = True
		break
	elif instruction in instruction_with_I_operand: # If the instruction can take only immediate data as an operand
		hexCodes.append(getHexCode_I_op(instruction, tokens[1]))
	elif instruction in instruction_with_R_operand: # If the instruction can take only register as an operand
		hexCodes.append(getHexCode_R_op(instruction, tokens[1]))
	elif instruction in instruction_with_MR_operand: # If the instruction can take the following types as an operand: memory, register
		hexCodes.append(getHexCode_MR_op(instruction, tokens[1]))
	elif instruction in instruction_with_IMR_operand: # If the instruction can take all the following types as an operand: immediate data, memory, register
		hexCodes.append(getHexCode_IMR_op(instruction, tokens[1]))
	else: # If the instruction is unknown
		syntaxErrorFound = True
		break

	if hexCodes[-1] == None: # If there was an error during  the hex code generation of the current line.
		syntaxErrorFound = True
		break

# Output file generation
outFile = open(sys.argv[1][:-4] + ".bin", "w")
if not syntaxErrorFound:
	#Syntax error free!
	for code in hexCodes:
		outFile.write(code + "\n")
else:
	outFile.write("Error!")
