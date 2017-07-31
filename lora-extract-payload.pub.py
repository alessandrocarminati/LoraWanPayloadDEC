from __future__ import division
from CryptoPlus.Cipher import AES
import base64
import math
from binascii import hexlify
from binascii import unhexlify
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("packet", help="Packet base64")
parser.add_argument("--quiet", help="Quiet", action="store_true")
args = parser.parse_args()
verb=True
if args.quiet:
   verb=False

# Put your lorawan  AppSKey here
#         00  01  02  03  04  05  06  07  08  09  0a  0b  0c  0d  0e  0f
aeskey="\xa2\x12\x0b\xe6\x3d\x55\xcb\x8b\x30\x70\x71\x65\xfe\xa1\xa6\xab"
payload=args.packet
data = base64.b64decode(payload)
num=math.ceil(len(data)/16)
a=[]
key=""
#-----------------------------------------------------------------------------------------------------------
#                          | Dir | Device Address     | Fcnt Up/Down       |      | Block number     
#-----------------------------------------------------------------------------------------------------------
#0x01 | 0x00 0x00 0x00 0x00| 0x00| 0x62 0x07 0xE0 0x02| 0xAA 0x00 0x00 0x00| 0x00 | 0x01
#0x01 | 0x00 0x00 0x00 0x00| 0x00| 0x62 0x07 0xE0 0x02| 0xAA 0x00 0x00 0x00| 0x00 | 0x02
cipher = AES.new(aeskey,AES.MODE_ECB)

for i in range(1, int(num+1)):
    a.append("\x01\x00\x00\x00\x00\x00"+data[1]+data[2]+data[3]+data[4]+data[6]+data[7]+"\x00\x00\x00"+chr(i))
    key=key+cipher.encrypt(a[i-1])

if verb:
   print "Payload b64 = "+payload
   print "data Hex=     "+hexlify(data)
   print "AppSkey =     "+hexlify(aeskey)
   print "Ai            "+hexlify(''.join(a))
   print "#A blocks=    "+str(int(num))
   print "---------------------------------"
   print "Xorkey=       "+ hexlify(key)
   print "---------------------------------"

decrypted = [ chr(ord(x) ^ ord(y)) for (x,y) in zip(data[9:], key) ]
if verb:
   print "Payload=      "+hexlify(''.join(decrypted))[:-8]
   print "Mic=          "+hexlify(''.join(decrypted))[8:]
else:
   print hexlify(''.join(decrypted))[:-8]

