import zlib
import os
import hashlib
import argparse
 
script_id = '43a7a70c_0'
patch_offset = 0x41C5
old_byte = 0xC7
new_byte = 0xC6
 
checksum_meta = '65fd027fd79ab051b4a49922c1f84f55'
 
def main(iMetaFile, oMetaFile):
	key = 0x00000000000000000078DA
	key = key.to_bytes(11, 'big')
 
	iMetaHash = hashlib.md5(open(iMetaFile, 'rb').read()).hexdigest()
	if iMetaHash != checksum_meta:
		inp = input('Warning!, unexpected hash for "global-metadata.dat". Please use the original metadata file. Input "y" to ignore and continue.')
		if inp != 'y':
			exit()
 
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
 
	os.makedirs(os.path.dirname(os.path.abspath(oMetaFile)), exist_ok=True)
	f2 = open(oMetaFile, 'wb')
	f2.write(metaObj)
	f2.close()
 
 
 
if __name__ == "__main__":
 
	parser = argparse.ArgumentParser()
	parser.add_argument('--input', '-i', default='./global-metadata.dat', help='Original global-metadata.dat')
	parser.add_argument('--output', '-o', default='patched/global-metadata.dat', help='Where to write the patched file')
 
	args = parser.parse_args()
 
	main(args.input, args.output)
 
