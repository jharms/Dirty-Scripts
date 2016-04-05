#!/usr/bin/python

import sys
import hashlib
from base64 import *
from binascii import *

reload(sys)
sys.setdefaultencoding('utf8')

if len(sys.argv) < 3:
	print "\nUsage: membercrack.py hashfile wordlist." 
	print "Make sure each line in the hashfile looks like:"
	print "<base64 encoded hash>:<base64 encoded salt> <- default"
	quit()

hf = sys.argv[1]
wordlist = sys.argv[2]
HASH = 0
SALT = 1
f = open(wordlist,'r')
found = 0
entries = []
hashfile = open(hf,'r')

for line in hashfile:
	entries.append(line.strip())

hashfile.close()

for word in f:

	for entry in entries:

		if len(entry.split(':')) != 2:
			print "Error processing this line: " + line
			print "Bye."
			quit()

		entry = entry.strip()
		h = entry.split(':')[HASH]
		s = entry.split(':')[SALT]
		h_h = hexlify(b64decode(h))
		s_h = hexlify(b64decode(s))

		if len(h_h) != 40:
			print "Error: hash length not 40 hex bytes (i.e. SHA1). Bye."
			quit()

		if len(s_h) != 32:
			print "Error: salt length not 32 hex bytes. Bye."
			quit()

		# algo : hash := sha1($salt | utf16le($password))
		testword = word.strip()
		testhash = hashlib.sha1(unhexlify(s_h) + testword.encode('UTF-16LE'))
		testhash = hexlify(testhash.digest())

		if testhash == h_h:
			# cracked
			print "[+] FOUND. The hash '" + h + "' is '" + testword + "'"
			found += 1

if found:
	print "Nice. Found " + str(found) + " hashes."
else:
	print "Sozz. Bad news. None cracked."

f.close()
