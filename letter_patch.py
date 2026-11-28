import zlib
import os
import sys
import hashlib

script_id = '43a7a70c_0'
patch_offset = 0x41C5
old_byte = 0xC7
new_byte = 0xC6

if getattr(sys, 'frozen', False):
	scriptPath = os.path.dirname(os.path.realpath(sys.executable))
else:
	scriptPath = os.path.dirname(os.path.realpath(__file__))

folder = os.path.join(scriptPath, 'patched')


try:
	os.mkdir(folder)
except:
	pass
 
checksum_meta = '65fd027fd79ab051b4a49922c1f84f55'
checksum_dll = '3A636051106B00EB4CB5579378E49DCF'

iMetaFile = os.path.join(scriptPath, 'Batenkaitos_Data','il2cpp_data','Metadata', 'global-metadata.dat')
oMetaFile = os.path.join(folder, 'global-metadata.dat')
oDllFile = os.path.join(folder, 'GameAssembly.dll')
iDllFile = os.path.join(scriptPath,  'GameAssembly.dll')

 
 

key = 0x00000000000000000078DA
key = key.to_bytes(11, 'big')

inp1 = 'y'
inp2 = 'y'

iMetaHash = hashlib.md5(open(iMetaFile, 'rb').read()).hexdigest()
if iMetaHash != checksum_meta:
	inp1 = input('Warning!, unexpected hash for "global-metadata.dat". Please use the original metadata file. Input "y" to ignore, and "s" to skip patching.\n')
	if inp1 not in ('y', 's'):
		exit()

idllHash = hashlib.md5(open(iDllFile, 'rb').read()).hexdigest()
if idllHash != checksum_dll.lower():
	inp2 = input('Warning!, unexpected hash for "GameAssembly.dll". Please use the original metadata file. Input "y" to ignore, and "s" to skip patching this file.\n')
	if inp2 not in ('y', 's'):
		exit()

if inp1 != 's':

	f = open(iMetaFile, 'rb')

	bBuffer = f.read()

	metaObj = bBuffer
	currentPos = 0
	ids = []
	patched = False

	while True:

		index = bBuffer.find(key, currentPos) - 3

		if index < 0:
			break

		f.seek(index)
		start = index - 4
		length = f.read(3)
		length = int.from_bytes(length, 'little')
		f.seek(index+12)
		myBytes = f.read(length+10)

		decomp = zlib.decompress(myBytes)

		checksum = zlib.adler32(decomp).to_bytes(4, 'big')
		fileID = int.from_bytes(decomp[4:8], 'big')
		fileID = str(hex(fileID))[2:]

		counter = 0
		iterator = True
		while iterator:
			if fileID + '_' + str(counter) in ids:
				counter += 1
			else:
				fileID = fileID + '_' + str(counter)
				iterator = False

		ids.append(fileID)

		currentPos = bBuffer.find(checksum) + 4

		f.seek(currentPos)

		zero = (currentPos - start) % 8

		if zero == 0:
			d_len = currentPos - start + 8
			zero = 8
		else:
			d_len = currentPos - start - zero + 8
			zero = 8 - zero

		if fileID == script_id:

			f.seek(index+12)
			myBytes = f.read(currentPos-index-12)

			if decomp[patch_offset] != old_byte:
				print('Unexpected byte at patch site in ' + fileID + ': ' + hex(decomp[patch_offset]))
				exit()

			decomp = (0).to_bytes(20, 'big') + decomp[20:]

			decomp = decomp[:patch_offset] + bytes([new_byte]) + decomp[patch_offset+1:]

			obj = zlib.compress(decomp, 9)

			while (len(obj)) % 8 != 0:
				obj = obj + (0).to_bytes(1, 'big')

			for x in range(zero):
				myBytes = myBytes + (0).to_bytes(1, 'big')

			while len(obj) < len(myBytes):
				obj = obj + (0).to_bytes(1, 'big')

			if len(obj) > len(myBytes):
				print(fileID)
				print('Warning compression too large. Patch does not fit.')
				exit()

			metaObj = metaObj.replace(myBytes, obj)
			metaObj = metaObj[:start+4] + len(decomp).to_bytes(4, 'little') + metaObj[start+8:]
			patched = True
			break

	f.close()

	if not patched:
		print('Script ' + script_id + ' was not found. Nothing written.')
		exit()

	f2 = open(oMetaFile, 'wb')
	f2.write(metaObj)
	f2.close()

os.makedirs(os.path.dirname(os.path.abspath(oMetaFile)), exist_ok=True)

if inp2 != 's':

	call = 'E8 50 9D 7E 02'
	offset1 = 0x192CCBB
	code = '53 56 57 48 83 EC 20 48 89 CB 89 D6 31 FF 48 89 D9 8D 14 3E 45 31 C0 45 31 C9 E8 21 63 81 FD FF C7 83 FF 4F 7C E8 48 83 C4 20 5F 5E 5B C3'
	offset2 = 0x4116A10

	f = open(iDllFile, 'rb')


	rBuffer = bytearray(f.read())

	ctx = bytes(rBuffer[offset1 - 3 : offset1 + 7])
	if ctx != bytes.fromhex('49 8B CE E8 90 00 00 00 EB AF'):
		print('Unexpected bytes at call site: ' + ctx.hex(' ').upper())
		exit()
	if rBuffer[offset2 : offset2 + 46] != bytes(46):
		print('Routine area is not zeroed. Nothing written.')
		exit()	

	rBuffer[offset1:offset1+len(bytes.fromhex(call))] = bytes.fromhex(call)
	rBuffer[offset2:offset2+len(bytes.fromhex(code))] = bytes.fromhex(code)

	f2 = open(oDllFile, 'wb')
	f2.write(rBuffer)

	f.close()
	f2.close()
