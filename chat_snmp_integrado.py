from scapy.all import *
import Queue
import time
from threading import Thread
import sys
import threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
import base64
import hashlib
from Tkinter import Tk, Label, Button, StringVar, Text, END, DISABLED
from threading import Thread
import time

if os.getuid() != 0: # Valida si el script esta siendo corrido como root
    print("Debes ejecutar este script como root.")
    sys.exit(1)

# Las siguientes lineas definen los argumentos
parser = argparse.ArgumentParser(description='Esta herramienta es un chat encubierto (covert channel) tipo client-to-client que utiliza el protocolo SNMP para intercambiar la informacion a traves de los OID en los paquetes tipo get-request. Para su uso es necesario que obligatoriamente defina tanto la IP origen (-l) asi como la IP destino (-d), la comunidad (-c) sirve como autenticacion y debe ser igual en ambos extremos, por defecto el valor de la comunidad es public, tambien los mensajes se pueden cifrar (-e) utilizando AES y la llave tambien debe ser igual en ambos extremos.')
parser.add_argument('-d', action="store",dest='IP_DESTINO', help=' IP destino')
parser.add_argument('-c', action="store",dest='COMUNIDAD', help='Valor de la comunidad SNMP')
parser.add_argument('-l', action="store",dest='IP_LOCAL', help='IP local')
args = parser.parse_args()

if len(sys.argv) == 1: # Obliga a mostrar el texto del 'help' sino hay argumentos ingresados.
 parser.print_help()
 sys.exit(1)

args = vars(args) # Convierte los argumentos en formato diccionario para facil manejo.



uport= 161 # Si no se ingresa el puerto, por defecto sera 161/UDP


if args['COMUNIDAD'] == None :
 communi= "public" # Si no se ingresa la comunidad , por defecto sera public
else:
 communi= args['COMUNIDAD']


llave= '' # si no especifica la llave los mensajes no se cifran



if args['IP_DESTINO'] == None :
 print "Ingrese la IP con la que se va comunicar" # En caso de que no ingrese la IP destino saldra este mensaje
 sys.exit()
else:
 peer = args['IP_DESTINO']


if args['IP_LOCAL'] == None :
 print "Ingrese su direccion ip" # En caso de que no ingrese la direccion IP local aparecera este mensaje
 sys.exit()
else:
 miip = args['IP_LOCAL']

#La siguiente clase define las funciones para cifrar y decifrar los mensajes con AES
'''
class AESCipher(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)  # utiliza vector de inicializacion para que el ciphertext de dos mensajes iguales sean diferentes
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)) # el ciphertext estara codificado en base64

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s): # definicion del pad
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
'''
# La siguiente funcion convierte el texto plano en un OID
def convertir (mensaje):
   if len(mensaje) > 128:
    print "es grande"
   oid ="1.3" # todos los oid enviados empiezan con 1.3
   for cont in range (0, len(mensaje)):
       des=str (ord(mensaje[cont]))
       oid = oid + "." + des
       je = len(mensaje) -1
       if cont == je:
        oid = oid + ".0" # todos los oid terminan en 0
   return oid

#esta funcion define el envio del paquete SNMP
def enviando (peer, communi, uport, oid ):
 p = IP(dst=args['IP_DESTINO'])/UDP(sport=RandShort(),dport=uport)/SNMP(community=communi,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
 send(p, verbose=0)

# esta funcion define el prn del sniff de scapy
def snmp_values(master):

    def sndr(pkt):
        eso=0
        a= " "
        d= " "
        pl = pkt[SNMP].community.val
        od = str(pl)
        s = pkt[SNMPvarbind].oid.val
        l = str(s)
        long= len(l) + 1

       	if od == communi:
         for i in range (4, len(l)):
	            if l[i] == ".":
                     e=chr(int(a))
                     d= d + e

                     a=" "
                    else:
         	     b=l[i]
                     a= a + b
         if d == " q":
            print " "
            print "My_friend abandono la sesion"
         else:
          print " "
          d = "My_friend: " + d + "\n"
          print d
          master.chatContainer.configure(state='normal')
          master.chatContainer.insert(END, d)
          master.chatContainer.configure(state=DISABLED)
        else:
         print "La autenticacion fallo, verifique el valor de la comunidad"

    return sndr

#esta funcion define el sniffer y los filtros necesarios para leer el paquete de entrada
def sniffer (puerto, peer, miip,master):
 filterstr= "udp and ip src " + peer +  " and port " +str(puerto)+ " and ip dst " +miip
 sniff(prn=snmp_values(master), filter=filterstr, store=0, count=10)
 return

class MyFirstGUI:
    def __init__(self, master, uport, communi, peer):
        self.master = master
        self.uport = uport
        self.communi = communi
        self.peer = peer
        master.title("A simple GUI")
        self.label_index = 0
        self.label_text = StringVar()
        self.label_text.set("TITULO")
        self.label = Label(master, textvariable=self.label_text)
        self.label.bind("<Button-1>", self.cycle_label_text)
        self.label.pack()

	# Chat container
	self.chatContainer = Text(master, height=10, width=30)
	self.chatContainer.config(state=DISABLED)
	self.chatContainer.pack()

	# Message container
	self.messageContainer = Text(master, height=2, width=30)
	self.messageContainer.pack()
        self.greet_button = Button(master, text="Send", command=self.sendMsg)
        self.greet_button.pack()

        self.close_button = Button(master, text="Close", command=self.closeConnection)
        self.close_button.pack()

	#thread = Thread(target = self.recieveMsg)
	#thread.start()

    def recieveMsg(self):
	for i in range(1,5):
	  texto = "HOLA N "+str(i)+"\n"
	  self.chatContainer.configure(state='normal')
	  self.chatContainer.insert(END, texto)
	  self.chatContainer.configure(state=DISABLED)
	  time.sleep(5)

    def sendMsg(self):
	texto = self.messageContainer.get("1.0",END)
	if texto and texto.strip():
	  print("Mensaje a enviar:")
	  self.messageContainer.delete('1.0', END)
	  self.chatContainer.configure(state='normal')
	  self.chatContainer.insert(END, texto)
	  self.chatContainer.configure(state=DISABLED)
	  oid=convertir(texto)
	  print("OID convertido: {}".format(oid))
	  enviando(peer, communi, uport,oid)
	  print(texto)

    def closeConnection(self):
	  print("Cerrando chat.")
	  self.master.quit()
	  sys.exit(0)

    def cycle_label_text(self, event):
        self.label_index += 1
        self.label_index %= len(self.LABEL_TEXT) # wrap around
        self.label_text.set(self.LABEL_TEXT[self.label_index])

alias = raw_input("Ingrese su nombre:")
print " "
print "Digite 'q' cuando quiera abandonar el chat"
print "Presione Enter para empezar y cada vez que reciba un mensaje"
print " "

root = Tk()
my_gui = MyFirstGUI(root, uport, communi, peer)

thread = Thread(target = sniffer, args = (uport,peer,miip,my_gui)) # craecion del thread para el  sniffer
thread.start()

root.mainloop()

#message= raw_input(alias + " ->")

#while message!= 'q':

#       message=raw_input(alias + "->")
#       if message!='':
#            oid=convertir(message)
#            enviando (peer, communi, uport,oid)
#            time.sleep(0.2)

print"gracias por utilizar el programa :). Presiona Ctrl + Z"
sys.exit()
