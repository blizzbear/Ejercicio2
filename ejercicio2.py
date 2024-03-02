import Crypto.Random
import Crypto.Util.number
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PyPDF2 import PdfReader, PdfWriter, PageObject
# Parámetros para Alice y Bob
bits = 1024
e = 65537

# Alice
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
dA = Crypto.Util.number.inverse(e, phiA)

# AC
pAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
phiAC = (pAC - 1) * (qAC - 1)
dAC = Crypto.Util.number.inverse(e, phiAC)

ruta_pdf_original = "NDA.pdf"
documento = PdfReader(ruta_pdf_original)
pagina = documento.pages[0]
pdf_original = pagina.extract_text()
hash_pdf = hashlib.sha256(pdf_original.encode()).hexdigest()
print("pdf hasheado: ",hash_pdf, "\n")
int_hash = int.from_bytes(hash_pdf.encode(), 'big')
print(int_hash,"\n")
firma_alice = pow(int_hash, dA, nA)
print("Alice firma")
print(firma_alice,"\n")
print("AC verifica la firma de alice ")
firma_descifrada = pow(firma_alice,e,nA)
print(firma_descifrada,"\n")

print("AC firma")
firma_AC = pow(firma_descifrada, dAC, nAC)
print(firma_AC,"\n")
print("Bob verifica la firma de AC")
firma_descifrada_AC = pow(firma_AC,e,nAC) 
print(firma_descifrada_AC,"\n")
contenido = str(firma_descifrada_AC)

