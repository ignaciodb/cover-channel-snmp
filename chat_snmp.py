# NAME: SNMP Covert Channel - Chat
# AUTHORS: Agustina Sgrinzi, Ignacio Bernardi & Matias Sena
# VERSION: 1.0

from scapy.all import *
import Queue
import time
from threading import Thread
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
from Tkinter import Tk, Label, Button, StringVar, Text, END, DISABLED

## GLOBALS
COMMUNITY = "public"    # Community to use for communication.
PORT = 161              # Port to use for communication. 161 = UDP.

## CLASSES
# This class manage the SNMP connection.
class SNMPManager:
    def __init__(self, ip_local, ip_destination):
        self.ip_local = ip_local
        self.ip_destination = ip_destination
        self.master = None

    # This func converts a text in a valid OID.
    def convertMsg(self, message):
        #if len(message) > 128:
            #print "es grande"
        oid = "1.3" # All OID sent start with 1.3
        for count in range (0, len(message)):
            des = str (ord(message[count]))
            oid = oid + "." + des
            je = len(message) - 1
            if count == je:
                oid = oid + ".0" # All OID sent end with .0
        return oid

    # This func sends our new message.
    def sendMsg(self, text):
        oid = self.convertMsg(text)
        packet = IP(dst=args['IP_DESTINO'])/UDP(sport=RandShort(),dport=PORT)/SNMP(community=COMMUNITY,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
        send(packet, verbose=0)

    # This func is called when a new SNMP packet arrives.
    def snmp_values(self):
        def sndr(pkt):
            a = " "
            message = " "
            pl = pkt[SNMP].community.val
            od = str(pl)
            s = pkt[SNMPvarbind].oid.val
            l = str(s)
            long = len(l) + 1
            for i in range (4, len(l)):
                if l[i] == ".":
                    e = chr(int(a))
                    message += e
                    a = " "
                else:
                    b = l[i]
                    a = a + b
            if message == " q":
                message = "Encubierto abandono la sesion."
            else:
                message = "Encubierto:" + message
            print ("\t" + message)
            self.master.chatContainer.configure(state='normal')
            self.master.chatContainer.insert(END, message + "\n")
            self.master.chatContainer.configure(state=DISABLED)
        return sndr

    # This func is called when a new packet is recieved.
    def recieveMsg(self):
        filterstr = "udp and ip src " + self.ip_destination +  " and port " +str(PORT)+ " and ip dst " + self.ip_local
        sniff(prn=self.snmp_values(), filter=filterstr, store=0, count=0)
        return

# This class manage the GUI used to chat.
class ChatGUI:
    def __init__(self, master, snmpConn):
        # Set window configurations.
        self.master = master
        master.resizable(width=False, height=False)
        master.minsize(width=500, height=300)
        root.protocol("WM_DELETE_WINDOW", self.closeConnection)
        self.snmpConn = snmpConn
        master.title("Covert Channel - SNMP")
        self.label_index = 0
        self.label_text = StringVar()
        self.label_text.set("CHAT")
        self.label = Label(master, textvariable=self.label_text)
        self.label.bind("<Button-1>", self.cycle_label_text)
        self.label.pack()
        # Render chat container.
        self.chatContainer = Text(master, height=15, width=60)
        self.chatContainer.config(state=DISABLED)
        self.chatContainer.pack()
        # Render message container.
        self.messageContainer = Text(master, height=2, width=60)
        self.messageContainer.pack()
        # Render buttons.
        self.sendButton = Button(master, text="Enviar", command=self.sendClicked)
        self.sendButton.pack()

    # This func is called when the SEND button is clicked.
    def sendClicked(self):
        textToSend = self.messageContainer.get("1.0",END)
        if textToSend and textToSend.strip():
            self.messageContainer.delete('1.0', END)
            self.chatContainer.configure(state='normal')
            self.chatContainer.insert(END, "Tu: " + textToSend)
            self.chatContainer.configure(state=DISABLED)
            self.snmpConn.sendMsg(textToSend)
            print("\tTu: " + textToSend)

    # This func is called when the CLOSE button is clicked.
    def closeConnection(self):
        print("[-] Covert Channel Chat ha finalizado.")
        self.snmpConn.sendMsg("q")
        self.master.quit()
        sys.exit(0)

    # Format the title label.
    def cycle_label_text(self, event):
        self.label_index += 1
        self.label_index %= len(self.LABEL_TEXT) # wrap around
        self.label_text.set(self.LABEL_TEXT[self.label_index])

# This class encrypts and decrypts the messages.
class CaesarCipher:
    def __init__(self):
        pass

## MAIN
if __name__ == "__main__":
    # Check if the script is run with ROOT.
    if os.getuid() != 0:
        print("El chat debe ser ejecutado como ROOT.")
        sys.exit(1)
    # Check needed arguments.
    parser = argparse.ArgumentParser(description='Esta herramienta es un chat encubierto (covert channel) tipo client-to-client que utiliza el protocolo SNMP para intercambiar la informacion a traves de los OID en los paquetes tipo get-request. Para su uso es necesario que obligatoriamente defina tanto la IP origen (-l) asi como la IP destino (-d).')
    parser.add_argument('-d', action="store",dest='IP_DESTINO', help=' IP destino')
    parser.add_argument('-l', action="store",dest='IP_LOCAL', help='IP local')
    args = parser.parse_args()
    if len(sys.argv) != 5: # Obliga a mostrar el texto del 'help' sino hay argumentos ingresados.
        parser.print_help()
        sys.exit(1)
    args = vars(args) # Convierte los argumentos en formato diccionario para facil manejo.
    # Check arg destination IP.
    if args['IP_DESTINO'] == None:
        print "[!] Ingrese la direccion IP con la que se va comunicar, con el parametro -d."
        sys.exit(1)
    else:
        ip_destination = args['IP_DESTINO']
    # Check arg local IP.
    if args['IP_LOCAL'] == None:
        print "[!] Ingrese su direccion IP, con el parametro -l."
        sys.exit(1)
    else:
        ip_local = args['IP_LOCAL']
    print("[-] Covert Channel Chat ha iniciado.")
    # Set the two needed objects.
    snmpConn = SNMPManager(ip_local, ip_destination)
    root = Tk()
    chatInterface = ChatGUI(root, snmpConn)
    snmpConn.master = chatInterface
    # Create the thread that will recieve the SNMP messages.
    thread = Thread(target = snmpConn.recieveMsg)
    thread.daemon = True
    thread.start()
    # GUI loop.
    root.mainloop()
