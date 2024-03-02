from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import Crypto.Random
import Crypto.Util.number
import PyPDF2

# Parámetros para Alice y Bob
bits = 1024
e = 65537

# Alice
p_alice = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
q_alice = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
n_alice = p_alice * q_alice
phi_alice = (p_alice - 1) * (q_alice - 1)
d_alice = Crypto.Util.number.inverse(e, phi_alice)

# Función para firmar digitalmente un mensaje
def firmar_documento(documento, llave_privada):
    h = SHA256.new(documento)
    firma = pkcs1_15.new(llave_privada).sign(h)
    return firma

# Crear un objeto de clave privada RSA
llave_privada_alice = RSA.construct((n_alice, e, d_alice))

# Leer el contrato NDA.pdf
ruta_contrato = "./NDA.pdf"
try:
    archivo_contrato = open(ruta_contrato, "rb")
    datos_contrato = archivo_contrato.read()
finally:
    archivo_contrato.close()

# Firmar digitalmente el contrato con la llave privada de Alice
firma_digital = firmar_documento(datos_contrato, llave_privada_alice)

# Guardar la firma digital en un archivo
ruta_firma = "firma_digital.dat"
try:
    archivo_firma = open(ruta_firma, "wb")
    archivo_firma.write(firma_digital)
finally:
    archivo_firma.close()

print("Firma digital generada y guardada en", ruta_firma)

