


#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


#                                     Can Download 2 goi pyshark va psutil de chay duoc chuong trinh nay


#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
import sys
import time
import tkinter as tk
from tkinter import Entry, Label, Menu, ttk
from tkinter.constants import END
from typing import Text
#from get_nic.getnic import interfaces
import pyshark
import os
from threading import Thread
from time import sleep
import threading
from tkinter import simpledialog

# --- Can download psutil bang lenh: pip install psutil
import psutil
#-------------------------------------------------------
import shutil
from tkinter.messagebox import showerror, showwarning, showinfo
from tkinter import filedialog as fd
import csv

flat=False
list=[]
capture=None
interfaceSelected=""
tmp_file="./tmp_file/tmp_file.pcap"
#tmp_file="tmp_file.pcap"
tmp_file_csv="./tmp_file/tmp_file.csv"
getcwd=str(os.getcwd())
listProtocol=["tcp","udp","arp","icmp","ftp","ssdp","ip","ipv6","icmpv6","http","dns","ssh","ssl","telnet","smtp","pop","imap","snmp","tls","nbns","ocsp","igmp"]


def detailPacket(no):
   return list[no-1]

def XuLyPacket(packet):
    len_layers=len(packet.layers)
    #--------tao cac bien chua du lieu ---------
    number=""
    time=""
    src_addr=""
    dst_addr=""
    src_port=""
    dst_port=""
    protocol=""
    length=""
    info=""

    if "TCP" in packet:         # la cac goi TCP, TLS,FTP,HTTP
        ip="ip"
        if "IPV6" in packet:
            ip="ipv6"

        src_addr=str(packet[ip].src)
        dst_addr=str(packet[ip].dst)
        src_port=str(packet.tcp.srcport)
        dst_port=str(packet.tcp.dstport)
        length=str(packet.length)
        number=str(packet.number)
        time=extractTime(packet.sniff_time)
        protocol=str(packet[len_layers-1]._layer_name).upper()

        if "HTTP" in packet:
            info=str(packet.http._all_fields.get("")).replace("\\r\\n","")
            protocol="HTTP"

        elif packet[len_layers-1]._layer_name=="tcp" or "DATA" in packet:

            info=str(src_port)+" -> "+str(dst_port)+" "+ TCPflag(str(packet.tcp._all_fields.get("tcp.flags.str")))
            protocol="TCP"

        elif packet[len_layers-1]._layer_name=="tls" or packet[len_layers-1]._layer_name=="_ws.short" :
            if "TLS" in packet:
               info=str(packet.tls._all_fields.get("tls.record"))
               protocol="TLS"
            else:
               info=src_port+" -> "+dst_port
               protocol= str(packet[len_layers-2]._layer_name).upper()
        else:
            info=str(src_port)+" -> "+str(dst_port)
            protocol=str(packet[len_layers-1]._layer_name).upper()

    elif "UDP" in packet: # co cac goi la DNS, SSDP, NBNS,   DHCPv6 co ip6, LLMNR co ip6 
        ip="ip"
        if "IPV6" in packet:
            ip="ipv6"

        number=str(packet.number)
        time=extractTime(packet.sniff_time)
        length=str(packet.length)
        src_addr=str(packet[ip].src)
        dst_addr=str(packet[ip].dst)
        src_port=str(packet.udp.srcport)
        dst_port=str(packet.udp.dstport)
        protocol=str(packet[len_layers-1]._layer_name).upper()

        if str(packet[len_layers-1]._layer_name)=="dhcpv6":
            info="DHCP version 6, Message type: " + str(packet[len_layers-1]._all_fields.get("dhcpv6.msgtype"))+" XID: "+str(packet[len_layers-1]._all_fields.get("dhcpv6.xid"))+" CID: "+str(packet[len_layers-1]._all_fields.get("dhcpv6.duid.bytes"))
            protocol="DHCPv6"
        elif str(packet[len_layers-1]._layer_name)=="dhcp":
            info1=""
            if str(packet[len_layers-1]._all_fields.get("dhcp.type")) =="2":
                info1="DHCP ACK (reply)"
            elif str(packet[len_layers-1]._all_fields.get("dhcp.type")) =="1":
                info1="DHCP Request"
            else:
                info1="DHCP"

            info=info1+" - Transaction ID " +str(packet[len_layers-1]._all_fields.get("dhcp.id"))  #----DHCP----

        elif str(packet[len_layers-1]._layer_name)=="ssdp" or packet[len_layers-1]._layer_name=="_ws.short":
            if "SSDP" in packet:
               info=str(packet.ssdp._all_fields.get("")).replace("\\r\\n", "")
               protocol="SSDP"
            else:
               info=src_port+" -> "+dst_port
               protocol= str(packet[len_layers-2]._layer_name).upper()

        elif str(packet[len_layers-1]._layer_name)=="dns" or str(packet[len_layers-1]._layer_name)=="llmnr":
            #protocol=str(packet[len_layers-1]._layer_name).upper()
            if str(packet[len_layers-1]._all_fields.get("dns.flags.response"))=="1":
                info="Standard query response " + str(packet[len_layers-1]._all_fields.get("dns.id")) +" "+ str(packet[len_layers-1]._all_fields.get("dns.qry.name"))
            else:
                info="Standard query " + str(packet[len_layers-1]._all_fields.get("dns.id")) +" "+ str(packet[len_layers-1]._all_fields.get("dns.qry.name"))

        elif str(packet[len_layers-1]._layer_name)=="nbns":
            if str(packet.nbns._all_fields.get("nbns.flags.opcode"))=="8":
                info="Refresh, type: "+str(packet.nbns._all_fields.get("nbns.type"))+" " + str(packet.nbns._all_fields.get("nbns.name"))
            elif str(packet.nbns._all_fields.get("nbns.flags.opcode"))=="0" :
                info="Name query, type: "+str(packet.nbns._all_fields.get("nbns.type"))+" " + str(packet.nbns._all_fields.get("nbns.name"))
            elif str(packet.nbns._all_fields.get("nbns.flags.opcode"))=="5" :
                info="Name Registration, type: "+str(packet.nbns._all_fields.get("nbns.type"))+" " + str(packet.nbns._all_fields.get("nbns.name"))
            elif str(packet.nbns._all_fields.get("nbns.flags.opcode"))=="6" :
                info="Name Release, type: "+str(packet.nbns._all_fields.get("nbns.type"))+" " + str(packet.nbns._all_fields.get("nbns.name"))
            elif str(packet.nbns._all_fields.get("nbns.flags.opcode"))=="7" :
                info="WACK (Wait for Acknowledgement), type: "+str(packet.nbns._all_fields.get("nbns.type"))+" " + str(packet.nbns._all_fields.get("nbns.name"))
            elif str(packet.nbns._all_fields.get("nbns.flags.opcode"))=="9" :
                info="WACK (Name Refresh (Alternate Opcode)), type: "+str(packet.nbns._all_fields.get("nbns.type"))+" " + str(packet.nbns._all_fields.get("nbns.name"))
            else:
                info="Multi-Homed Name Registration"+str(packet.nbns._all_fields.get("nbns.type"))+" " + str(packet.nbns._all_fields.get("nbns.name"))
        elif "DATA" in packet:
            info=src_port+" -> "+dst_port+" Len="+str(packet[len_layers-1]._all_fields.get("data.len"))
            protocol="UDP"  
        else:
            info=src_port+" -> "+dst_port

    elif "ARP" in packet:
        target_ip=str(packet.arp._all_fields.get("arp.dst.proto_ipv4"))
        sender_ip=str(packet.arp._all_fields.get("arp.src.proto_ipv4"))

        number=str(packet.number)
        time=extractTime(packet.sniff_time)
        src_addr=str(packet.eth._all_fields.get("eth.src"))
        dst_addr=str(packet.eth._all_fields.get("eth.dst"))
        protocol="ARP"
        length=str(packet.length) #ARP ko co port

        if str(packet.arp._all_fields.get("arp.opcode"))=="1": # la goi Request
            info="Who has "+target_ip+"? Tell "+sender_ip
        elif str(packet.arp._all_fields.get("arp.opcode"))=="2":
            info=sender_ip+" is at "+str(packet.arp._all_fields.get("arp.src.hw_mac"))
        else:
            info=sender_ip+" ---> "+target_ip
        #thistuple=(number,time,src_addr,dst_addr,protocol,length,info)

    elif "TCP" not in packet and "UDP" not in packet: #la cac goi ICMP
        ip="ip"
        if "IPV6" in packet:
            ip="ipv6"

        number=packet.number
        #time=packet.sniff_time
        time=extractTime(packet.sniff_time)
        length=packet.length
        src_addr=str(packet[ip].src)
        dst_addr=str(packet[ip].dst)
        protocol=str(packet[len_layers-1]._layer_name).upper()
        if "ICMP" in packet:
            protocol="ICMP"
            info=ICMPtype(int(packet.icmp._all_fields.get("icmp.type")))
        elif "ICMPV6" in packet:
            protocol="ICMPv6"
            info="ICMP with IP version 6, Type: "+ (packet.icmpv6._all_fields.get("icmpv6.type"))

        #/////--------can bo sung-------
        elif "IGMP" in packet:
            protocol="IGMP"
            info="IGMP version "+packet[len_layers-1]._all_fields.get("igmp.version")
        else:
            info="XXXXXXXXXXXXXXX"
    thistuple=(number,time,src_addr,dst_addr,protocol,length,info)
    return thistuple



def extractTime(x):
    time =str(x.hour)+":"+str(x.minute)+":"+str(x.second)+","+str(x.microsecond)
    return time


def getInterface():
      interfaces=psutil.net_if_addrs()
      listInterface=[]
      for x in interfaces.keys():
         listInterface.append(x)
      tubles=tuple(listInterface)
      print(tubles)
      return tubles
def setInterface(x):
       global interfaceSelected
       interfaceSelected=x
       print("ham set interface:")
       print(x)

def extractTime(x):
    #time =str(packet.sniff_time.hour)+":"+str(packet.sniff_time.minute)+":"+str(packet.sniff_time.second)+"."+str(packet.sniff_time.microsecond)
    time =str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"."+str(x.microsecond)
    return time

def ICMPtype(x):
    dic={
        0: "Echo reply",
        3: "Destination unreachable",
        4: "Source quench",
        5: "Redirect",
        8: "Echo request",
        9: "Router advertisement",
        10: "Router selection",
        11: "Time exceeded",
        12: "Parameter problem",
        13: "Timestamp",
        14: "Timestamp reply",
        15: "Information request",
        16: "Information reply",
        17: "Address mask request",
        18: "Address mask reply",
        30: "Traceroute",
        31: "Datagram Conversion Error",
        32: "Mobile Host Redirect",
        33: "IPv6 Where-Are-You",
        34: "IPv6 I-Am-Here",
        35: "Mobile Registration Request",
        36: "Mobile Registration Reply",
        37: "Domain Name Request",
        38: "Domain Name Reply",
        39: "SKIP",
        40: "Security Failures"
    }
    return dic[x]


def TCPflag(x):
    flags=""
    listFlag=[]
    for j in x:
        if j == "F":
            listFlag.append("FIN")
        elif j =="S":
            listFlag.append("SYN")
        elif j =="R":
            listFlag.append("RST")
        elif j =="P":
                listFlag.append("PSH")
        elif j =="A":
                listFlag.append("ACK")
        elif j =="U":
                listFlag.append("URG")
                
    if len(listFlag)==1:
        flags="["+listFlag[0]+"]"
            
    elif len(listFlag)==2:
        
        flags="[" + listFlag[1] + ", " + listFlag[0] +"]"
    elif len(listFlag)==3:
        
        flags="[" + listFlag[2] + ", " + listFlag[1] + ", " + listFlag[0] +"]"
    else:
        flags=[]
        
    return flags

#Luong chay lien tuc de bat cac Packet
class Capture(Thread):
      def __init__(self,interface,window):
            super().__init__()
            self.interface=interface
            self.window=window

      def run(self):
            global flat
            global capture

            fileCSV=open(tmp_file_csv,"w",newline="")
            writer=csv.writer(fileCSV)
            writer.writerow(("No","Time","Source","Destination","Protocol","Length","Info"))

            if flat==True:
                try:
                    print("ham run:" +interfaceSelected)
                    capture = pyshark.LiveCapture(interface=self.interface,output_file=tmp_file)
                    for packet in capture:
                        thistuble=XuLyPacket(packet)
                        self.window.tree.insert("",tk.END,values=thistuble)
                        #print(thistuble)
                        list.append(packet)
                        sleep(0.1)
                        #---------Luu vao file csv------------
                        writer.writerow(thistuble)
                        if flat==False:
                            capture.close()
                            fileCSV.close()
                        print("---------"+str(packet.number)+"------------")

                except Exception as e:
                    print(e)
                    #print("loi")
                    #pass

                finally:
                    #capture.close()
                    print("finaly---------")
                    flat=False


class App(tk.Tk):
      def __init__(self):
            super().__init__()
            self.title("Capture Packet")
            self.geometry("1450x800")
            #----theme-----
            s = ttk.Style()
            #s.theme_use("clam")
            #s.theme_use("winnative")
            s.theme_use("alt")
            #s.theme_use("default")
            #s.theme_use("classic")
            #s.theme_use("vista")
            #s.theme_use("xpnative")
            s.configure('Treeview.Heading',foreground="blue",font=("times",13))
            #--------dung de kiem tra dieu khien luu Khi chuong trinh chua bat goi
            self.flatSave=False
            #--------cac lenh configure ------
            self.iconbitmap("kiet.ico")
            self.resizable(0,0)
            self.rowconfigure(0,weight=2)
            self.rowconfigure(1,weight=1)

            self.rowconfigure(2,weight=10)
            self.rowconfigure(3,weight=10)
            self.rowconfigure(4,weight=10)
            self.rowconfigure(5,weight=7)
            self.option_var = tk.StringVar(self)
            self.listInterface = getInterface()
            #------ tao cac widget----
            self.createWG()
            self.createFilter()
            self.createText1()
            self.createText2()
            self.option_changed()

      def exit(self):
         self.destroy()
      
      
      def clear_all_tree_view(self):
         for item in self.tree.get_children():
            self.tree.delete(item)

      def stop(self):
         global flat
         global capture
         flat=False
         self.btnFilter["state"]=tk.NORMAL
         """
         try:
            capture.close()
            if self.thread.is_alive:
                capture.close()
         except Exception as e:
            print(e)
                  """
                  
         #self.thread.do_run=False
         
         #for t in self.thread:
          #   t.signal=False
         self.frameButton.btnStart["state"]=tk.NORMAL
         self.frameButton.btnStop["state"]=tk.DISABLED
         self.frameButton.btnClose["state"]=tk.NORMAL
         
         #print("chieu dai: ",len(list))
        
         #capture.close()
             
             
                        
         #self.thread.join()
        
         
         #self.updateText2()
         
         #self.updateText1()
         #print(flat)

      def start(self):
         global flat
         flat=True
         #bat co Save khi da co du lieu
         self.flatSave=True
         self.btnFilter["state"]=tk.DISABLED
         print(flat)
         #self.frameTable.text1.delete("1.0",END)
         #self.frameTable.text1.delete("1.0",END)
         self.clear_all_tree_view()
         self.frameDetail.text2.configure(state="normal")
         self.frameDetail.text2.delete("1.0",END)
         self.frameDetail.text2.configure(state="disable")
         self.update()
         global list
         print("--------qua start--------")
         list.clear()

         self.frameButton.btnStop["state"]=tk.NORMAL
         self.frameButton.btnStart["state"]=tk.DISABLED
         self.frameButton.btnClose["state"]=tk.DISABLED
         self.thread=Capture(interfaceSelected,self)
         self.thread.start()
         
         #self.updateText1()
         self.monitor(self.thread)
         
         #self.run_button()
         #sleep(0.5)
      def openFile(self):
          
        if flat ==True:
            showerror(title="Canh bao",message="Khong the mo goi tin trong khi dang bat goi!!!!")
        else:
            
            #----Tat co Save khi du lieu dang dang Open--- luc nay se ko co du lieu( mac du luu van dc, van co  du lieu---do Luu chi la copy tu file tmp co san)
            self.flatSave=False

            filetypes = (
                ("pcap files", "*.pcap"),
                ("pcapng files", "*.pcapng"))

            filename = fd.askopenfilename(
            title="Open a file .pcap/.pcapng",
            initialdir='/',
            filetypes=filetypes)
            
            print(filename)
            if filename=="":
                print("Chua mo file")
            else:
                self.clear_all_tree_view()
                self.frameDetail.text2.configure(state="normal")
                self.frameDetail.text2.delete("1.0",END)
                self.frameDetail.text2.configure(state="disable")
                list.clear()
                captureFile=None
                
                captureFile = pyshark.FileCapture(filename)
                for packet in captureFile:
                    
                    try:
                        thistuble=XuLyPacket(packet)
                    except Exception as e:
                        print(e)
                        continue
                    self.tree.insert("",tk.END,values=thistuble)
                    list.append(packet)
                    
                
                captureFile.close()
                print("finaly---------")
        
            
            
      def emty(self):
         pass
            
      def createWG(self):

         #--------Tao Menu ----------
         self.menubar =Menu(self)
         self.config(menu=self.menubar)
         #menu File
         file_menu=Menu(self.menubar,tearoff=False)
         file_menu.add_command(label="Open",command=self.openFile)
         file_menu.add_command(label="Close",command=self.exit)
         file_menu.add_command(label="Save",command=self.save)
         file_menu.add_command(label="Quit",command=self.exit)
         self.menubar.add_cascade(label="File",menu=file_menu,underline=0)
         file_menu=Menu(self.menubar,tearoff=False)
         #Menu Go
         go_menu=Menu(self.menubar,tearoff=False)
         go_menu.add_command(label="Go to packet",command=self.emty)
         go_menu.add_command(label="Next packet",command=self.emty)
         go_menu.add_command(label="Previous packet",command=self.emty)
         go_menu.add_command(label="First packet",command=self.emty)
         go_menu.add_command(label="Last packet",command=self.emty)
         go_menu.entryconfig("Go to packet",state="disable")
         self.menubar.add_cascade(label="Go",menu=go_menu,underline=0)
         #Menu Capture
         capture_menu=Menu(self.menubar,tearoff=False)
         capture_menu.add_command(label="Option...",command=self.emty)
         capture_menu.add_command(label="Start",command=self.start)
         capture_menu.add_command(label="Stop",command=self.stop)
         capture_menu.add_command(label="Capture Filters...",command=self.exit,state="disabled")
         capture_menu.entryconfig("Stop",state="disable")
         self.menubar.add_cascade(label="Capture",menu=capture_menu,underline=0)
         #Menu Analyze
         analyze_menu=Menu(self.menubar,tearoff=False)
         analyze_menu.add_command(label="Display Filters...",command=self.emty)
         analyze_menu.add_command(label="Follow TCP Stream",command=self.emty)
         analyze_menu.add_command(label="Follow UDP Stream",command=self.emty)
         self.menubar.add_cascade(label="Analyze",menu=analyze_menu,underline=0)
         #Menu Help
         help_menu=Menu(self.menubar,tearoff=False)
         help_menu.add_command(label="Sample Captures",command=self.emty)
         help_menu.add_command(label="About...",command=self.emty)
         self.menubar.add_cascade(label="Help",menu=help_menu,underline=0)


         #--------Tao frame Button----------
         self.frameButton=ttk.Frame(self,border=2)
         self.frameButton['padding'] = (5,5,5,5)
         #self.frameButton['relief'] = 'sunken'
         self.frameButton.rowconfigure(0,weight=1)
         self.frameButton.grid(row=0,column=0,sticky="W")
         #--------Tao Button----------
         self.frameButton.btnStart=tk.Button(self.frameButton,text="Start",command=self.start,foreground="red",activebackground='green', activeforeground='white',font=("Helvetica", 12,"bold"))
         self.frameButton.btnStart.grid(row=0,column=0,sticky="W")

         self.frameButton.btnStop=tk.Button(self.frameButton,text="Stop",command=self.stop,foreground="red",activebackground='green',activeforeground='white',font=("Helvetica", 12,"bold"))
         self.frameButton.btnStop["state"]=tk.DISABLED
         self.frameButton.btnStop.grid(row=0,column=1,sticky="W")

         self.frameButton.btnClose=tk.Button(self.frameButton,text="Close",command=self.exit,foreground="red",activebackground='green', activeforeground='white',font=("Helvetica", 12,"bold"))
         self.frameButton.btnClose.grid(row=0,column=5)

         self.frameButton.btnSave=tk.Button(self.frameButton,text="Save",foreground="red",activebackground='green', activeforeground='white',font=("Helvetica", 12,"bold"))
         self.frameButton.btnSave["command"]=self.save
         self.frameButton.btnSave.grid(row=0,column=4)

         self.frameButton.btnOpen=tk.Button(self.frameButton,text="Open",command=self.openFile,foreground="red",activebackground='green',activeforeground='white',font=("Helvetica", 12,"bold"))
         self.frameButton.btnOpen.grid(row=0,column=3)

         self.frameButton.btnSaveCSV=tk.Button(self.frameButton,text="Save file CSV",command=self.saveCSV,foreground="red",activebackground='green',activeforeground='white',font=("Helvetica", 12,"bold"))
         self.frameButton.btnSaveCSV.grid(row=0,column=6)

         # label
         paddings = {'padx': 7, 'pady': 7}
         labelInterface= ttk.Label(self.frameButton,  text="Select Interface:")
         labelInterface.grid(column=7, sticky=tk.E,row=0,**paddings,rowspan=2)
        # option menu
         option_menu = ttk.OptionMenu(
            self.frameButton,
            self.option_var,
            self.listInterface[0],
            *self.listInterface,command=self.option_changed)

         option_menu.grid(column=8, row=0,**paddings,sticky="W",rowspan=2)




      def option_changed(self, *args):
            global interfaceSelected
            interfaceSelected=self.option_var.get()
            print("ham option_changed")
            
            print(self.option_var.get())
            print(type(self.option_var.get()))
            print(interfaceSelected)
            

      def monitor(self,thread):
            if thread.is_alive():
            # check the thread every 100ms
               self.after(70, lambda: self.monitor(thread))
            else:
                
               self.frameButton.btnStart['state'] = tk.NORMAL
               
      def clear_entry(self,event, entry):
            entry.delete(0, END)
            self.btnFilter["state"]=tk.NORMAL
            #entry.unbind('<Button-1>', self.clear_entry)
      def createFilter(self):
          
            self.frameFilter = ttk.Frame(self)
            self.frameFilter.columnconfigure(0,weight=2)
            self.frameFilter.columnconfigure(1,weight=1)
            self.frameFilter.grid(row=1,column=0,sticky="W")
             
            self.filterText = tk.StringVar()
            self.textboxFilter = ttk.Entry(self.frameFilter, textvariable=self.filterText)
            #self.textboxFilter.focus()
            self.textboxFilter.grid(row=0,column=0,sticky="W")
            
            self.btnFilter = tk.Button(self.frameFilter, text="Confirm", command=self.filter,activebackground='blue', activeforeground='white')
            self.btnFilter.grid(row=0,column=1,sticky="W")
            
            placeholder_text = "Input filter..."
            self.textboxFilter.insert(0, placeholder_text)
            self.textboxFilter.bind("<Button-1>", lambda event: self.clear_entry(event, self.textboxFilter))
            
            if self.filterText.get()=="Input filter...":
                self.btnFilter["state"]=tk.DISABLED
            
      def filter(self):
            print(self.filterText.get())
            data=str(self.filterText.get()).strip()
            
            if len(list)==0:
                print("Loi,chua co du lieu!!")
                showerror(title="Error",message="Can nhan vao Start hoac Open de co du lieu truoc!!")
            
            elif data =="":
                    
                #----xoa cac frame du lieu---
                self.clear_all_tree_view()
                self.frameDetail.text2.configure(state="normal")
                self.frameDetail.text2.delete("1.0",END)
                self.frameDetail.text2.configure(state="disable")
                self.update()
                print("Co du lieu!!")
                for packet in list:
                    thistuble=XuLyPacket(packet)
                    self.tree.insert("",tk.END,values=thistuble)
            
            elif data.startswith("ip.addr=="):
                data=data.replace("ip.addr==", "")
                print("loc theo ipaddr "+data)
                
                print("Co du lieu!!")
                #ham loc theo ipv4
                self.filterIpAddr(data)
                
            elif data in listProtocol:
                print("loc theo protocal name")
                print("Co du lieu!!")
                #ham loc theo protocol name
                self.filterProtocol(data)
            else:
                print("Du lieu nhap sai hoac chuong trinh chua ho tro filter nay")
                showerror(title="Error",message="Ban nhap sai cu phap hoac filter nay chua duoc cai tren chuong trinh nay")
                
                
      def filterProtocol(self,protocolName):
            #----xoa cac frame du lieu---
            self.clear_all_tree_view()
            self.frameDetail.text2.configure(state="normal")
            self.frameDetail.text2.delete("1.0",END)
            self.frameDetail.text2.configure(state="disable")
            self.update()
            #--------bat dau loc va ghi du lieu vao frame 1,2
            for packet in list:
                if protocolName.upper() in packet:
                    thistuble=XuLyPacket(packet)
                    self.tree.insert("",tk.END,values=thistuble)

      
      def filterIpAddr(self,ipAddr):
            #----xoa cac frame du lieu---
            self.clear_all_tree_view()
            self.frameDetail.text2.configure(state="normal")
            self.frameDetail.text2.delete("1.0",END)
            self.frameDetail.text2.configure(state="disable")
            self.update()
            #--------bat dau loc va ghi du lieu vao frame 1,2
            for packet in list:
                if "IP" in packet:
                    if ipAddr==packet.ip.dst or ipAddr==packet.ip.src:
                        thistuble=XuLyPacket(packet)
                        self.tree.insert("",tk.END,values=thistuble)
      def createText1(self):
            #--------Tao frame cho table tree----------
            self.frameTable=ttk.Frame(self,border=5)
            self.frameTable['padding'] = (5,5,5,5)
            self.frameTable['relief'] = 'sunken'

            self.frameTable.grid(row=2,column=0,rowspan=2)
            columns = ("no", "time", "source", "destination", "protocol", "length", "info")
            self.tree = ttk.Treeview(self.frameTable, columns=columns, show="headings",height= 19)

            # define headings
            self.tree.heading("no", text="No.")
            self.tree.heading("time", text="Time")
            self.tree.heading("source", text="Source")
            self.tree.heading("destination", text="Destination")
            self.tree.heading("protocol", text="Protocol")
            self.tree.heading("length", text="Length")
            self.tree.heading("info", text="Info")

            self.tree.bind("<<TreeviewSelect>>",self.item_selected)
            self.tree.grid(row=0, column=0, sticky=tk.W,rowspan=2)
            # add a scrollbar
            scrollbar = ttk.Scrollbar(self.frameTable, orient=tk.VERTICAL, command=self.tree.yview)
            self.tree.configure(yscroll=scrollbar.set)
            scrollbar.grid(row=0, column=1, sticky="ns",rowspan=2)

      def item_selected(self, event):
         for selected_item in self.tree.selection():
            item = self.tree.item(selected_item)
            record = item["values"]
            no=int(record[0])
            
            #print("len cua list: ",len(list))
            #print(list)
            
            #show detail ben duoi frameDetail
            self.frameDetail.text2.configure(state="normal")
            self.frameDetail.text2.delete("1.0",END)
            self.frameDetail.text2.insert(1.0,detailPacket(no))
            self.frameDetail.text2.configure(state="disable")
            # show a message
            #showinfo(title='Information', message=','.join(record))

      def createText2(self):
              #--------Tao frame cho table tree----------
            self.frameDetail=ttk.Frame(self,border=3,relief="solid",height=600)
            self.frameDetail['padding'] = (3,3,3,3)
            #self.frameDetail['relief'] = 'sunken'
            self.frameDetail.grid(row=4,column=0,rowspan=2)
            self.frameDetail.text2=tk.Text(self.frameDetail,border=2,width=165,pady=0,padx=0,height=15,state="disabled")
            self.frameDetail.text2.grid(row=0,column=0,pady=5)

            self.frameDetail.scrollbar = ttk.Scrollbar(self.frameDetail, orient='vertical', command=self.frameDetail.text2.yview)
            self.frameDetail.scrollbar.grid(row=0, column=1, sticky='ns')

            #  communicate back to the scrollbar
            self.frameDetail.text2['yscrollcommand'] = self.frameDetail.scrollbar.set


      def updateText2(self):
            print("----da qua day-------")
            self.frameDetail.text2.insert(1.0,"kiet ngu si l nhat luono")

      def createPopup(self):
            self.popup=tk.Toplevel(width=600,height=400)
            k=Entry(self.popup,textvariable="Duong dan",width=300)
            k.focus()
            k.grid(row=1,column=0)
            btn=tk.Button(self.popup,text="OK" )
            btn.grid(row=2,column=0)
            
      def save(self):

            
            if self.flatSave==False:
                showerror(title="Canh bao",message="Loi, khong co du lieu!!!!")
            
            elif flat==True:
                showerror(title="Canh bao",message="Khong the luu goi tin trong khi dang bat goi!!!!")
            else:
                newFile=self.createSimpledialog()
                if str(newFile)!=".":
                    source = tmp_file
                    # chinh sua tai day de chay dc may o ban
                    #destination = "./save_file/"+newFile+".pcap"
                    destination = newFile+".pcap"
                    print(destination)
                    try:
                        shutil.copy2(source, destination)
                        showinfo(title="Thong bao",message="Da luu file thanh cong. Kiem tra tai thu muc hien hanh: "+getcwd)
                        #print("File copied successfully.")
                    
                    # If source and destination are same
                    except shutil.SameFileError:
                        #print("Source and destination represents the same file.")
                        showerror(title="Thong bao",message="Source and destination represents the same file.")
                    
                    
                    # If destination is a directory.
                    #except IsADirectoryError:
                        #   print("Destination is a directory.")
                    
                    # If there is any permission issue
                    #except PermissionError:
                        #   print("Permission denied.")
                    
                    # For other errors
                    except:
                        showerror(title="Thong bao",message="Error occurred while copying file.")
                        #print("Error occurred while copying file.")
                    
                
      def saveCSV(self):
    
            if self.flatSave==False:
                showerror(title="Canh bao",message="Loi, khong co du lieu!!!!")
            
            elif flat==True:
                showerror(title="Canh bao",message="Khong the luu trong khi dang bat goi!!!!")
            else:
                newFile=self.createSimpledialogCSV()
                if str(newFile)!=".":
                    source = tmp_file_csv
                    # chinh sua tai day de chay dc may o ban
                    #destination = "./save_file/"+newFile+".csv"
                    destination = newFile+".csv"
                    print(destination)
                    try:
                        shutil.copy2(source, destination)
                        showinfo(title="Thong bao",message="Da luu file thanh cong. Kiem tra tai thu muc hien hanh: "+getcwd)
                        #print("File copied successfully.")
                    
                    # If source and destination are same
                    except shutil.SameFileError:
                        #print("Source and destination represents the same file.")
                        showerror(title="Thong bao",message="Source and destination represents the same file.")
                    
                    
                    # If destination is a directory.
                    #except IsADirectoryError:
                        #   print("Destination is a directory.")
                    
                    # If there is any permission issue
                    #except PermissionError:
                        #   print("Permission denied.")
                    
                    # For other errors
                    except:
                        showerror(title="Thong bao",message="Error occurred while copying file.")
                        #print("Error occurred while copying file.")
      
    

      def createSimpledialog(self):
            answer=simpledialog.askstring("Save File PCAP","Nhap ten file muon luu (Khong nhap phan mo rong .pcap)",parent=self)
            """
            print(os.path.exists("./save_file/"+str(answer)))
            print("./save_file/"+str(answer))

            if os.path.exists("./save_file/"+str(answer)+".pcap")==True:
                showwarning(title="Thong bao",message="File nay da ton tai!")
                return "."
            elif answer is not None:
                print("Ten file la: ", answer)
                return answer
            else:
                print("Ban chua nhap ten file?")
                return "."
            """
            
            print(os.path.exists(str(answer)+".pcap"))
            print(str(answer))

            if os.path.exists(str(answer)+".pcap")==True:
                showerror(title="Thong bao",message="File "+getcwd+"\\"+str(answer)+".pcap da ton tai!")
                return "."
            elif answer is not None:
                print("Ten file la: ", answer)
                return answer
            else:
                print("Ban chua nhap ten file?")
                return "."
            
            
            
      def createSimpledialogCSV(self):
            answer=simpledialog.askstring("Save File CSV","Nhap ten file muon luu (Khong nhap phan mo rong .csv)",parent=self)
            """
            print(os.path.exists("./save_file/"+str(answer)))
            print("./save_file/"+str(answer))

            if os.path.exists("./save_file/"+str(answer)+".csv")==True:
                showwarning(title="Thong bao",message="File nay da ton tai!")
                return "."
            elif answer is not None:
                print("Ten file la: ", answer)
                return answer
            else:
                print("Ban chua nhap ten file?")
                return "."
            """
            
            print(os.path.exists(str(answer)+".csv"))
            print(str(answer))

            if os.path.exists(str(answer)+".csv")==True:
                #showerror(title="Thong bao",message="File nay da ton tai!")
                showerror(title="Thong bao",message="File "+getcwd+"\\"+str(answer)+".csv da ton tai!")
                return "."
            elif answer is not None:
                print("Ten file la: ", answer)
                return answer
            else:
                print("Ban chua nhap ten file?")
                return "."


if __name__ == "__main__":
   app = App()
   app.mainloop()
