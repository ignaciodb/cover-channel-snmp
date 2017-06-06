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
from Tkinter import *
from PIL import ImageTk, Image

## GLOBALS
COMMUNITY = "UBAMSI"    # Community to use for communication.
PORT = 162              # Port to use for communication.
TRAPID = 14452          # ID of the SNMP trap.

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
        packet = IP(dst=self.ip_destination)/UDP(sport=RandShort(),dport=PORT)/SNMP(community=COMMUNITY,PDU=SNMPtrapv2(id=TRAPID,varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
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
            self.master.chatContainer.configure(state='normal')
            if message == " q":
                message = "- Encubierto se ha desconectado -\n"
                self.master.chatContainer.insert(END, message, "bold")
            else:
                self.master.chatContainer.insert(END, " > Encubierto:", "bold")
                self.master.chatContainer.insert(END, message)
                message = "Encubierto:" + message
            print ("\t" + message)
            self.master.chatContainer.configure(state=DISABLED)
            self.master.chatContainer.see(END)
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
        self.master.protocol("WM_DELETE_WINDOW", self.closeConnection)
        self.snmpConn = snmpConn
        path = re.sub(__file__, '', os.path.realpath(__file__))
        path = path + "/images/CovertMan.png"
        self.picCovertMan = PhotoImage(file=path)
        master.tk.call('wm', 'iconphoto', master._w, self.picCovertMan)
        master.title("Covert Channel - SNMP")
        # Create first Frame for rendering.
        frameOne = Frame(self.master, width=500, height=80)
        frameOne.pack(fill="both", expand=True)
        frameOne.grid_propagate(False)
        frameOne.grid_rowconfigure(0, weight=1)
        frameOne.grid_columnconfigure(0, weight=1)
        panel = Label(frameOne, image = self.picCovertMan)
        panel.image = self.picCovertMan
        panel.grid(row=0, padx=2, pady=2)
        # Create second Frame for rendering.
        frameTwo = Frame(self.master, width=500, height=300)
        frameTwo.pack(fill="both", expand=True)
        frameTwo.grid_propagate(False)
        frameTwo.grid_rowconfigure(0, weight=1)
        frameTwo.grid_columnconfigure(0, weight=1)
        self.chatContainer = Text(frameTwo, relief="sunken", font=("Myriad Pro", 10), spacing1=10, fg="white", borderwidth=0, highlightthickness=1, bg="black")
        self.chatContainer.tag_configure("bold", font=("Myriad Pro", 10, "bold"))
        self.chatContainer.config(wrap='word', state=DISABLED, highlightbackground="dark slate gray")
        self.chatContainer.grid(row=0, sticky="nsew", padx=5, pady=5)
        self.scrollb = Scrollbar(frameTwo, command=self.chatContainer.yview, borderwidth=0, highlightthickness=0, bg="dark slate gray")
        self.scrollb.grid(row=0, column=1, sticky='ns', padx=2, pady=5)
        self.chatContainer['yscrollcommand'] = self.scrollb.set
        frameThree = Frame(self.master, width=500, height=50)
        frameThree.pack(fill="both", expand=True)
        frameThree.grid_propagate(False)
        frameThree.grid_rowconfigure(0, weight=1)
        frameThree.grid_columnconfigure(0, weight=1)
        self.messageContainer = Text(frameThree, height=2, width=50, font=("Myriad Pro", 10),borderwidth=0, highlightthickness=1)
        self.messageContainer.config(highlightbackground="dark slate gray")
        self.messageContainer.grid(row=0, sticky="nsew", padx=5, pady=5)
        self.sendButton = Button(frameThree, text="Enviar", command=self.sendClicked, font=("Myriad Pro", 10), bg="black", fg="#d9d9d9", borderwidth=0, highlightthickness=1)
        self.sendButton.config(highlightbackground="dark slate gray",activebackground="dark slate gray")
        self.sendButton.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)

    # This func is called when the SEND button is clicked.
    def sendClicked(self):
        textToSend = self.messageContainer.get("1.0",END)
        if textToSend and textToSend.strip():
            self.messageContainer.delete('1.0', END)
            self.chatContainer.configure(state='normal')
            self.chatContainer.insert(END, " > Tu: ","bold")
            self.chatContainer.insert(END, textToSend)
            self.chatContainer.configure(state=DISABLED)
            self.chatContainer.see(END)
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
