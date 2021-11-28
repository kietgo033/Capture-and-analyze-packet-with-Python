
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
import psutil
import shutil
from tkinter.messagebox import showerror, showwarning, showinfo
from tkinter import filedialog as fd


flat=False
list=[]
capture=None
interfaceSelected=""
#tmp_file="./tmp_file/tmp_file.pcap"
tmp_file="tmp_file.pcap"



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
            info=packet.http._all_fields.get("")
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
               info=str(packet.ssdp._all_fields.get(""))
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
            self.signal=True
         
      def run(self):
            global flat
            global capture
            i=0
            if flat==True:
               try:
                  print("ham run:" +interfaceSelected)
                  capture = pyshark.LiveCapture(interface=self.interface,output_file=tmp_file)
                  for packet in capture:
                     #print(packet)
                     
                     thistuble=XuLyPacket(packet)
                     
                     self.window.tree.insert("",tk.END,values=thistuble)
                     print(thistuble)
                     list.append(packet)
                     #self.window.update()
                     sleep(0.1)
                     
                     if flat==False:
                         capture.close()
                     print("---------------------")
                     #time.sleep(0.5)
               except Exception:
                  print("loi")
                  pass
               
               finally:
                  #capture.close()
                  print("finaly---------")
                  flat=False


class App(tk.Tk):
      def __init__(self):
            super().__init__()
            self.title("Capture Packet")
            self.geometry("1450x800")
            
            s = ttk.Style()
            s.theme_use("clam")
            s.configure('Treeview.Heading', background="")
            
            self.resizable(0,0)
            self.rowconfigure(0,weight=2)
            self.rowconfigure(1,weight=1)
            
            self.rowconfigure(2,weight=10)
            self.rowconfigure(3,weight=10)
            self.rowconfigure(4,weight=10)
            self.rowconfigure(5,weight=7)
            #self.columnconfigure(0,weight=1)
            self.option_var = tk.StringVar(self)
            self.listInterface = getInterface()
            self.createWG()
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
         
         print("chieu dai: ",len(list))
        
         #capture.close()
             
             
                        
         #self.thread.join()
        
         
         #self.updateText2()
         
         #self.updateText1()
         #print(flat)

      def start(self):
         global flat
         flat=True
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
         self.frameButton.btnStart=tk.Button(self.frameButton,text="Start",command=self.start)
         self.frameButton.btnStart.grid(row=0,column=0,sticky="W")
         
         self.frameButton.btnStop=tk.Button(self.frameButton,text="Stop",command=self.stop)
         self.frameButton.btnStop["state"]=tk.DISABLED
         self.frameButton.btnStop.grid(row=0,column=1,sticky="W")

         self.frameButton.btnClose=tk.Button(self.frameButton,text="Close",command=self.exit)
         self.frameButton.btnClose.grid(row=0,column=5)
         
         self.frameButton.btnSave=tk.Button(self.frameButton,text="Save")
         self.frameButton.btnSave["command"]=self.save
         self.frameButton.btnSave.grid(row=0,column=4)
         
         self.frameButton.btnOpen=tk.Button(self.frameButton,text="Open",command=self.openFile)
         self.frameButton.btnOpen.grid(row=0,column=3)

         # label
         paddings = {'padx': 7, 'pady': 7}
         labelInterface= ttk.Label(self.frameButton,  text="Select Interface:")
         labelInterface.grid(column=6, sticky=tk.E,row=0,**paddings,rowspan=2)
        # option menu
         option_menu = ttk.OptionMenu(
            self.frameButton, 
            self.option_var,
            self.listInterface[0],
            *self.listInterface,command=self.option_changed)

         option_menu.grid(column=7, row=0,**paddings,sticky="W",rowspan=2)


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
               
      
      def createText1(self): 
            #--------Tao frame cho table tree----------
            self.frameTable=ttk.Frame(self,border=5)
            self.frameTable['padding'] = (5,5,5,5)
            self.frameTable['relief'] = 'sunken'
            #self.frameTable.rowconfigure(0,weight=1)
            #self.frameTable.rowconfigure(1,weight=1)
            self.frameTable.grid(row=2,column=0,rowspan=2)
             
            #self.frameTable.text1=tk.Text(self.frameTable,height=20  ,width=160,pady=10)
            #self.frameTable.text1.grid(row=0,column=0,padx=7,pady=10)
            
            
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

            #self.tree.column("no", width=3,anchor="w")

            #self.tree.column("time", width=15, anchor=tk.W)
            #self.tree.column("protocol",width=70,anchor=tk.W)

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
            #self.frameDetail.rowconfigure(0,weight=1)
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

            newFile=self.createSimpledialog()
            
            if str(newFile)!=".":
                source = tmp_file
                # chinh sua tai day de chay dc may o ban
                destination = "./save_file/"+newFile+".pcap"
                

                try:
                    shutil.copy2(source, destination)
                    showinfo(title="Thong bao",message="Da luu file thanh cong. Kiem tra tai thu muc ./save_file")
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
            answer=simpledialog.askstring("Input","Nhap ten file muon luu (Khong nhap phan mo rong)",parent=self)
            
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




if __name__ == "__main__":
   app = App()
   app.mainloop()
