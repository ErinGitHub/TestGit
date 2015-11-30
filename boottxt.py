# boottxt.py
from distutils.core import setup
import py2exe

#setup(console=["boottxt.py"])

import hashlib
import os
import sys
import math
import time
#---------- SHA256-----------------
# return value:
#    fMidHash: int, 32 bytes
def sha256_IDT(filename, onlyname):
    f = open(filename, 'rb')
    fdata = f.read()
    fMidHash = 0
    print(hex(len(fdata)))
    for i in range(0, len(fdata)/256):
      fMidData = fdata[i*256:i*256+256]
      sh = hashlib.sha256()
      sh.update(fMidData)
      hexdigest = sh.hexdigest()
      fMidHash = fMidHash ^ int(hexdigest, 16)
    hashf = open('hash.txt', 'w')
    hashf.write(hex(fMidHash))
    hashf.close()
    #print (hex(fMidHash),"*",onlyname )
  
    f.close()
    return fMidHash  # type int
#---------- RSA2048 -----------------    
def GetDataFromFile(filename):
    f = open(filename)
    n = int(f.read(),16)
    '''
    print('*'*77)
    print(filename)
    print(hex(n))
    print('*'*77)
    '''
    return (n)
    
def my_RSA_encrypt(src, d, n):
    x = pow(src, d, n)
    '''
    print('*'*77)
    print("Encrypted Data is:")
    print(hex(x))
    print('*'*77)
    '''
    return x   # type int
    
def my_RSA_decrypt(src, e, n):
    y = pow(src, e, n)
    '''
    print('*'*77)
    print("Decrypted Data is:")
    print(hex(y))
    print('*'*77)
    '''
    return y # type int  
    
#--------- crc16----------------------
class crc16:  
    
    auchCRC = [0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129,\
	         0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF, 0x1231, 0x0210, 0x3273, 0x2252,\
	         0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C,\
	         0xF3FF, 0xE3DE, 0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,\
	         0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D, 0x3653, 0x2672,\
	         0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738,\
	         0xF7DF, 0xE7FE, 0xD79D, 0xC7BC, 0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861,\
	         0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,\
	         0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC,\
	         0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 0x6CA6, 0x7C87, 0x4CE4, 0x5CC5,\
	         0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B,\
	         0x8D68, 0x9D49, 0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,\
	         0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78, 0x9188, 0x81A9,\
	         0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3,\
	         0x5004, 0x4025, 0x7046, 0x6067, 0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C,\
	         0xE37F, 0xF35E, 0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,\
	         0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3,\
	         0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xA7DB, 0xB7FA, 0x8799, 0x97B8,\
	         0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676,\
	         0x4615, 0x5634, 0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,\
	         0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3, 0xCB7D, 0xDB5C,\
	         0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16,\
	         0x0AF1, 0x1AD0, 0x2AB3, 0x3A92, 0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B,\
	         0x9DE8, 0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,\
	         0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36,\
	         0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0] 
    def __init__(self):  
        pass 
         
    def createarray(self,array):  
        crcvalue = self.createcrc(array)  
        array.append(crcvalue>>8)  
        array.append(crcvalue&0xff)  
        return array      
    def calcrc(self,array):  
        crchi = 0xff  
        crclo = 0xff  
        lenarray = len(array)  
        for i in range(0,lenarray-2):  
            crcIndex = crchi ^ array[i]  
            crchi = crclo ^ self.auchCRCHi[crcIndex]  
            crclo = self.auchCRCLo[crcIndex]  
        if crchi == array[lenarray-2] and crclo== array[lenarray-1] :  
            return 0  
        else:  
            return 1  
    def calcCRC(self, array):
        crchi = 0xff  
        crclo = 0xff 
        for i in range(0,len(array)):  
            crcIndex = crchi ^ array[i] 
            auchCRCH = self.auchCRC[crcIndex]>>8
            auchCRCL = self.auchCRC[crcIndex]&0xff
            crchi = crclo ^ auchCRCH  
            crclo = auchCRCL  
        return (crchi<<8 | crclo)

#-------- File Processing -----------------------------------
class myfilePro:  
    
    def writeline(self, txtfile_232, txtfile_usb, asciidata):
        if(txtfile_232):
          txtfile_232.write(asciidata.upper())
          txtfile_232.write('\n')
          
        if(txtfile_usb):
          #usbcmd = conv_usb_cmdline(asciidata)
          #txtfile_usb.write(usbcmd.upper())
          txtfile_usb.write(asciidata.upper())
          txtfile_usb.write('\n')
        return
        
    def writecmdline(self, txtfile_232, txtfile_usb, asciicmd):
        if(txtfile_232):
          txtfile_232.write('SEND:')        
          txtfile_232.write(asciicmd.upper())
          txtfile_232.write('\n')
        
        if(txtfile_usb):
          txtfile_usb.write('SEND:')        
          usbcmd = conv_usb_cmdline(asciicmd)
          txtfile_usb.write(usbcmd.upper())
          txtfile_usb.write('\n')
        return
    
    def writerespline(self, txtfile_232, txtfile_usb):
        strresp = FormKioskIIICmdStr(0xc7, 0, 0, 0)
        
        if(txtfile_232):
          txtfile_232.write('WAIT:')        
          txtfile_232.write(strresp.upper())
          txtfile_232.write('\n')
          
        if(txtfile_usb):
          txtfile_usb.write('WAIT:')
          usbcmd = conv_usb_cmdline(strresp)        
          txtfile_usb.write(usbcmd.upper())
          txtfile_usb.write('\n')
        
        
#--------- Data Processing -------------------------------
#--- 0x5669564f -> "5669544f" ---
def int2str(intdat):
    str=hex(intdat)
    end = len(str) -1
    if(str[end]=='L'):
      end -= 1
    start = 2
      
    str = str[start:end+1]
    if(end%2==0): # need prefix 0
      str = '0' + str
    return str
    
#--- "5669544f" -> [0x56,0x69,0x54,0x4f] ---    
def str2iarry(mystr): #convert string to byte array
    length = len(mystr)
    array = [0]
    if(length%2): # need prefix 0
      mystr='0' + mystr        
    for i in range(0, length/2):
      B = int(mystr[i*2:(i*2+2)],16)
      array.append(B)
    array = array[1:len(array)]
    return array

#--- [0x56,0x69,0x54,0x4f] -> "5669544f" ---      
def iarry2str(iarry):
    str = ''.join(int2str(i) for i in iarry)
    return str
        
def FormKioskIIICmdArray(icmd, isubcmd, strdata, strlen):
    cmd = [0x56,0x69,0x56,0x4F,0x74,0x65,0x63,0x68,0x32,0x00]
    
    cmd.append(icmd)
    cmd.append(isubcmd)
    
    if(strlen):     
      iarray = str2iarry(strdata)
      length = len(iarray)
      cmd.append(length>>8)
      cmd.append(length&0xff)
      for i in range(0, len(iarray)):
        cmd.append(iarray[i])
    else:
      cmd.append(0)
      cmd.append(0)
    crctool = crc16()
    crc = crctool.calcCRC(cmd)
    cmd.append(crc>>8)
    cmd.append(crc&0xff)      
    return cmd # byte array
    
def FormKioskIIICmdStr(icmd, isubcmd, strdata, strlen):
    cmd = [0x56,0x69,0x56,0x4F,0x74,0x65,0x63,0x68,0x32,0x00]
    
    cmd.append(icmd)
    cmd.append(isubcmd)
    if(strlen):
      iarray = str2iarry(strdata)
      length = len(iarray)
      cmd.append(length>>8)
      cmd.append(length&0xff)
      #iarray = str2iarry(strdata)
      for i in range(0, len(iarray)):
        cmd.append(iarray[i])
    else:
      cmd.append(0)
      cmd.append(0)
    crctool = crc16()
    crc = crctool.calcCRC(cmd)
    cmd.append(crc>>8)
    cmd.append(crc&0xff)
    strcmd = iarry2str(cmd)      
    return strcmd # command string
    
def conv_usb_cmdline(asciidata):
        
    EP1_SIZE = 64
    SINGLE_PACKET_REPORT_ID = '01'
    FIRST_REPORT_ID = '02'
    CONTINUATION_REPORT_ID = '03'
    LAST_REPORT_ID = '04'
        
    #dataset split to blocks, 63*2 bytes each (ascII char)
    blksize = (EP1_SIZE - 1)*2    # ascII char here, so multi 2
    datalen = len(asciidata)
    m = datalen%blksize
    #padding 0
    for i in range(0, (blksize-m)):
      asciidata += '0'
      datalen += 1
    #datalen now is the final length  
    if (datalen%blksize):
      print('length error!!!!!!!!!!')
          
    firstpacket = 1
    blknum = 0
    usbdata = '0'
    while(datalen > 0):
      if(datalen > blksize):
        if( firstpacket ):
          usbdata += FIRST_REPORT_ID
        else:
          usbdata += CONTINUATION_REPORT_ID
      else:
        if(firstpacket):
          usbdata += SINGLE_PACKET_REPORT_ID
        else:
          usbdata += LAST_REPORT_ID
            
      usbdata += asciidata[blknum*blksize:(blknum+1)*blksize]
      blknum += 1
      datalen -= blksize
      firstpacket = 0
      
      if(len(usbdata[1:])%64):
        print(len(usbdata[1:]))
        print('error!!!!!!!!!!')
          
    return  usbdata[1:]
#-------- send check value in Activation (C7-2A) --------------------------
# ienccv: encrypted check value, type int, 256 bytes
def  WriteCommandActivateCheckValue(txtfile, ienccv):
    strcv = int2str(ienccv)      
    strcmd = FormKioskIIICmdStr(0xc7, 0x2a, strcv, len(strcv))
    fpro = myfilePro()
    fpro.writecmdline(txtfile, 0, strcmd)
    return                
#-------- enter bootloader (C7-41) --------------------------
def  WriteCommandEnterBoot(txtfile_232, txtfile_usb):
    strcmd = FormKioskIIICmdStr(0xc7, 0x41, 0, 0)
    fpro = myfilePro()
    #--- write to txt file for RS232 --------
    fpro.writeline(txtfile_232, txtfile_usb, "<START:")
    fpro.writeline(txtfile_232, txtfile_usb, "TIMEOUT:1000")
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)
    fpro.writeline(txtfile_232, txtfile_usb, "SLEEP:2000")
    
    #--- write to txt file for usbhid --------
    return
#-------- get version (C7-10) -------------------------------
def  WriteCommandGetVersion(txtfile_232, txtfile_usb):
    strcmd = FormKioskIIICmdStr(0xc7, 0x10, 0, 0)
    fpro = myfilePro()
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)
    fpro.writerespline(txtfile_232, txtfile_usb)
    return    
#-------- start update (C7-11) -------------------------------
def  WriteCommandStartUpdate(txtfile_232, txtfile_usb):
    strcmd = FormKioskIIICmdStr(0xc7, 0x11, 0, 0)
    fpro = myfilePro()
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)
    fpro.writerespline(txtfile_232, txtfile_usb)
    return                                                     
    
#-------- erase flash (C7-12) -------------------------------
#itype: 1-erase application, 2-erase bootloader space, 3-erase app and bl space
def  WriteCommandEraseFlash(txtfile_232, txtfile_usb, itype):      
    strcmd = FormKioskIIICmdStr(0xc7, 0x12, int2str(itype), 1)
    fpro = myfilePro()
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)
    fpro.writerespline(txtfile_232, txtfile_usb)
    return
#-------- send check value (C7-13) --------------------------
# ienccv: encrypted check value, type int, 256 bytes
# imethod: 1- send encrypted check value  0- send clear check value
def  WriteCommandSendCheckValue(txtfile_232, txtfile_usb, ienccv, imethod):
    strcv = int2str(ienccv)   
    if(imethod == 1):   
      strcmd = FormKioskIIICmdStr(0xc7, 0x13, strcv, len(strcv))
    else:
      strcmd = FormKioskIIICmdStr(0xc7, 0x23, strcv, len(strcv))
    fpro = myfilePro()
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)
    fpro.writerespline(txtfile_232, txtfile_usb)
    return
#-------- send data (C7-14) ---------------------------------
# XXXXXXXXXXXienccv: encrypted check value, type int, 256 bytes
# currently, ienccv is plaint check value, type int, 32 bytes
# zone_type: 1, app zone, start from 0x30000; 2, boot1 zone, start from 0x1000; 3, boot2 zone, start from 0x78000
def WriteCommandSendAppdata(txtfile_232, txtfile_usb, ienccv, strAppdata, blknum, zone_type):
    #strcmd ='\0'
    targInt = 0
    #blksize=256
    blksize=32
    start_addr = 0x20000 #0x30000
    
    if zone_type == 1:  
      start_addr = 0x20000
      strcmd = '00'
    elif (zone_type == 2):
      start_addr = 0x8000
      strcmd = '00' #'0000'
    elif zone_type == 3:
      start_addr = 0x14000
      strcmd = '00'
    else:
      print('zone_type error!')
      return
      
    if(len(strAppdata)==2048): # write 2048 bytes each time
      addr = blknum * 2048 + start_addr
      #strcmd = '00'
      if(addr < 0x10000):
        strcmd += '00'  
      strcmd += int2str(addr)
      strord = int2str(ord(strAppdata[0]))
      for i in range(1, 2048):
         strord += int2str(ord(strAppdata[i]))
      #print('**********')
      #print(len(strord))
      #print(blksize)
      for i in range(0, len(strord)/(blksize*2)):
         targInt =  ienccv^int(strord[i*blksize*2:(i+1)*blksize*2], 16)
         strmid = int2str(targInt)
         if(len(strmid)<64):
           strnew = '0'
           kk = 63 - len(int2str(targInt))
           for j in range(0, kk):
             strnew += '0'
           #print('----------')
           #print(strnew)
           #print(strcmd)
           strmid = strnew + strmid
           #print(strmid)
           #print(len(strmid))
           #print('----------')
         strcmd += strmid   
      
    else:
      print("WriteCommandSendAppdata: strAppdata length error!")
    
    if(len(strcmd) != 4104):
      print('111 error!!!!!!!!!!!!!!!!!!!')
      print(len(strcmd))
      print(strcmd)
    
    strcmd = FormKioskIIICmdStr(0xc7, 0x14, strcmd, len(strcmd))
    fpro = myfilePro()
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)
    fpro.writerespline(txtfile_232, txtfile_usb)
    return  
#-------- end update (C7-15) --------------------------------
def  WriteCommandEndUpdate(txtfile_232, txtfile_usb):
    strCurrDate=time.strftime('%Y%m%d', time.localtime(time.time()))
    iarray = [0]
    for i in range(0, len(strCurrDate)):
      iarray.append(ord(strCurrDate[i]))
    iarray = iarray[1:]
    strdate = iarry2str(iarray)
    strcmd = FormKioskIIICmdStr(0xc7, 0x15, strdate, len(strCurrDate))
    fpro = myfilePro()
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)             
    fpro.writerespline(txtfile_232, txtfile_usb)
    return
#-------- start application (C7-16) -------------------------
def  WriteCommandStartApp(txtfile_232, txtfile_usb):
    strcmd = FormKioskIIICmdStr(0xc7, 0x16, 0, 0)
    fpro = myfilePro()
    fpro.writecmdline(txtfile_232, txtfile_usb, strcmd)
    fpro.writerespline(txtfile_232, txtfile_usb)
    fpro.writeline(txtfile_232, txtfile_usb, "END>")
    return

#itype: 1-erase application, 2-erase bootloader space, 3-erase app and bl space(not supported)    
def GenerateBootAppTXT(filename, itype):
    #-- 0. open firmware bin file -------------------------------
    path =  sys.path[0]
    #print(path)
    list1=os.listdir(path)
    #filename = 'KIOSKIII_2013.bin'

    #-- 1. calulate file data hash in fHash(32 bytes) -------------------
    intHash = sha256_IDT(path +'\\'+ filename, filename)
    print(hex(intHash))

    #-- 2. encrypte hash by firmware private key (256 bytes) ----
    plaintData = intHash

    fname = path + "\\Firm_private_d.txt"
    d = GetDataFromFile(fname)

    fname = path + "\\Firm_N.txt"
    n = GetDataFromFile(fname)

    encryptedData = my_RSA_encrypt(plaintData, d, n)
    #print(type(encryptedData))
    #-- 3. generate download firmware file ----------------------
    bootfile_232 = open("boot_app_RS232.txt", 'w')
    bootfile_usb = open("boot_app_USBHID.txt", 'w')
    #----- 3.1  enter bootloader ------------
    WriteCommandEnterBoot(bootfile_232, bootfile_usb)
    #----- 3.2  get version -----------------
    WriteCommandGetVersion(bootfile_232, bootfile_usb)
    
    WriteCommandStartUpdate(bootfile_232, bootfile_usb)
    #----- 3.3  erase flash -----------------
    WriteCommandEraseFlash(bootfile_232, bootfile_usb, 1)
    #----- 3.4  send check value ------------
    WriteCommandSendCheckValue(bootfile_232, bootfile_usb, encryptedData, 0)
    #----- 3.5  send data ------------------- 
    fmfile = open(filename, 'rb')
    fmdata = fmfile.read()
    blksize = 2048
    for i in range(0, len(fmdata)/blksize):
      datablock = fmdata[i*blksize:(i+1)*blksize]
      #WriteCommandSendAppdata(bootfile, encryptedData, datablock, i)
      WriteCommandSendAppdata(bootfile_232, bootfile_usb, intHash, datablock, i, 0x30000)
      
    #----- 3.6  end update ------------------
    WriteCommandEndUpdate(bootfile_232, bootfile_usb)
    #----- 3.7  start app -------------------
    WriteCommandStartApp(bootfile_232, bootfile_usb)
    #-- 4. close file ----------------------------------------
    bootfile_232.close()
    bootfile_usb.close()
    fmfile.close()
    return

def test():
    #-- 0. open firmware bin file -------------------------------
    path =  sys.path[0]
    #print(path)
    list1=os.listdir(path)
    filename = 'KIOSKIII_2013.bin'
    
    fmfile = open(filename, 'rb')
    fmdata = fmfile.read()
    
    intHash = sha256_IDT(filename, filename)    
    blksize = 2048    
    datblk = fmdata[11*blksize:12*blksize]
    
    targInt = 0
    blksize=32
    
    ii = 0x123
    str1 = int2str(ii)
    print(str1)
    print(len(str1))
    
    if(len(datblk)==2048): # write 2048 bytes each time
      addr = 12 * 2048 + 0x30000
      strcmd = '00'
      strcmd += int2str(addr)
      strord = int2str(ord(datblk[0]))
      for i in range(1, 2048):
         strord += int2str(ord(datblk[i]))
      print('**********')
      print(len(strord))
      print(blksize)
      for i in range(0, len(strord)/(blksize*2)):
         targInt =  intHash^int(strord[i*blksize*2:(i+1)*blksize*2], 16)
         strmid = int2str(targInt)
         if(len(strmid)<64):
           strnew = '0'
           kk = 63 - len(int2str(targInt))
           for j in range(0, kk):
             strnew += '0'
           print('----------')
           print(strnew)
           #print(strcmd)
           strmid = strnew + strmid
           print(strmid)
           print(len(strmid))
           print('----------')
         strcmd += strmid 
           
    else:
      print('error')
    
    print(len(strcmd))     
    return

#itype: 1-erase application, 2-erase bootloader space, 3-erase app and bl space(not supported)   
#iMethod: 1- check value encypted  0- check value is plaint
def GenerateBootTXT(AppFname, Boot1Fname, Boot2Fname, itype, iMethod):
    #-- 0. open firmware bin file -------------------------------
    path =  sys.path[0]
    #print(path)
    list1=os.listdir(path)
    #filename = 'KIOSKIII_2013.bin'

    #-- 1. calulate file data hash in fHash(32 bytes) -------------------
    if(itype&0x01):
      intHash = sha256_IDT(path +'\\'+ AppFname, AppFname)
      print(hex(intHash))
    else:
      intHash = sha256_IDT(path +'\\'+ Boot1Fname, Boot1Fname)
      print(hex(intHash))
      
    #-- 2. encrypte hash by firmware private key (256 bytes) ----
    plaintData = intHash

    fname = path + "\\Firm_private_d.txt"
    d = GetDataFromFile(fname)

    fname = path + "\\Firm_N.txt"
    n = GetDataFromFile(fname)

    encryptedData = my_RSA_encrypt(plaintData, d, n)
    #print(type(encryptedData))
    #-- 3. generate download firmware file ----------------------
    if(iMethod == 1):
      bootfile_232 = open("boot_app_enc_RS232.txt", 'w')
      bootfile_usb = open("boot_app_enc_USBHID.txt", 'w')
    else:
      bootfile_232 = open("boot_app_clr_RS232.txt", 'w')
      bootfile_usb = open("boot_app_clr_USBHID.txt", 'w')
    #----- 3.1  enter bootloader ------------
    WriteCommandEnterBoot(bootfile_232, bootfile_usb)
    #----- 3.2  get version -----------------
    #WriteCommandGetVersion(bootfile_232, bootfile_usb)
    
    WriteCommandStartUpdate(bootfile_232, bootfile_usb)
    #----- 3.3  erase flash -----------------
    WriteCommandEraseFlash(bootfile_232, bootfile_usb, itype)
    #----- 3.4  send check value ------------
    if(iMethod == 1):
      WriteCommandSendCheckValue(bootfile_232, bootfile_usb, encryptedData, iMethod)
    else:
      WriteCommandSendCheckValue(bootfile_232, bootfile_usb, intHash, iMethod)
    #----- 3.5  send data -------------------
    if(itype&0x01):
      fmfile = open(AppFname, 'rb')
      fmdata = fmfile.read()
      blksize = 2048
      for i in range(0, len(fmdata)/blksize):
        datablock = fmdata[i*blksize:(i+1)*blksize]
        #WriteCommandSendAppdata(bootfile, encryptedData, datablock, i)
        WriteCommandSendAppdata(bootfile_232, bootfile_usb, intHash, datablock, i, 1)
    
    if(itype&0x02):
      #write boot1
      fmfile = open(Boot1Fname, 'rb')
      fmdata = fmfile.read()
      blksize = 2048
      for i in range(0, len(fmdata)/blksize):
        datablock = fmdata[i*blksize:(i+1)*blksize]
        #WriteCommandSendAppdata(bootfile, encryptedData, datablock, i)
        WriteCommandSendAppdata(bootfile_232, bootfile_usb, intHash, datablock, i, 2)
      #write boot2
      fmfile = open(Boot2Fname, 'rb')
      fmdata = fmfile.read()
      blksize = 2048
      for i in range(0, len(fmdata)/blksize):
        datablock = fmdata[i*blksize:(i+1)*blksize]
        #WriteCommandSendAppdata(bootfile, encryptedData, datablock, i)
        WriteCommandSendAppdata(bootfile_232, bootfile_usb, intHash, datablock, i, 3)

    #----- 3.6  end update ------------------
    WriteCommandEndUpdate(bootfile_232, bootfile_usb)
    #----- 3.7  start app -------------------
    WriteCommandStartApp(bootfile_232, bootfile_usb)
    #-- 4. close file ----------------------------------------
    bootfile_232.close()
    bootfile_usb.close()
    fmfile.close()
    return
        
def GenerateBootAppOnlyTXT(iMethod):
    #path = 'D:\\Projects\\KisocIII\\K3_SH_NewBoot\\Release_R\\Exe\\'
    filename = 'KIOSKIII_2013.bin'
    
    #filename = path + filename
    GenerateBootTXT(filename, 0, 0, 1, iMethod)
    return
    
def GenerateBootBootOnlyTXT(iMethod):
    #path1 = 'D:\\Projects\\KisocIII\\K3_SRED\\Bootloader_new\\Bootloader-k21-512-part2\\Boot1\\Exe\\'
    #path2 = 'D:\\Projects\\KisocIII\\K3_SRED\\Bootloader_new\\Bootloader-k21-512-part2\\Boot2\\Exe\\'
    
    boot1name = 'BL1.bin'#'KIOSKIII_BOOT1.bin'
    boot2name = 'BL2.bin'#'KIOSKIII_BOOT2.bin'
    
    #boot1name = path1 + boot1name
    #boot2name = path2 + boot2name
    GenerateBootTXT(0, boot1name, boot2name, 2, iMethod)

def GenerateBootBothTXT(iMethod):
    #path_app = 'D:\\Projects\\KisocIII\\K3_SH_NewBoot\\Release_R\\Exe\\'
    #path1 = 'D:\\Projects\\KisocIII\\K3_SRED\\Bootloader_new\\Bootloader-k21-512-part2\\Boot1\\Exe\\'
    #path2 = 'D:\\Projects\\KisocIII\\K3_SRED\\Bootloader_new\\Bootloader-k21-512-part2\\Boot2\\Exe\\'
    
    appname = 'KIOSKIII_2013.bin'
    boot1name = 'BL1.bin'#'KIOSKIII_BOOT1.bin'
    boot2name = 'BL2.bin'#'KIOSKIII_BOOT2.bin'
    
    #appname = path_app + appname
    #boot1name = path1 + boot1name
    #boot2name = path2 + boot2name
    GenerateBootTXT(appname, boot1name, boot2name, 3, iMethod)
    
def Do():
    while True:
      print("Please choose your selection index:")
      sel = raw_input("1. Generate Main Application Only\n2. Generate Boot Loader Only\n3. Generate Main Application and Boot Loader\n")
      try:
        sel = int(sel)
      except ValueError:
        print ("Please enter a number!\n")
        continue
        
      if  sel < 1 or sel > 3:
        print ("Please enter an appropriate index!\n")
        continue
        
      if sel == 1:
        print('GenerateBootAppOnlyTXT')
        GenerateBootAppOnlyTXT(1)
        GenerateBootAppOnlyTXT(0)
        break;
      elif sel ==2:
        GenerateBootBootOnlyTXT(1)
        GenerateBootBootOnlyTXT(0)
        break;
      else:
        GenerateBootBothTXT(1)
        GenerateBootBothTXT(0)
        break;
        
    return

def GetActivateCVCommand():
    filename = "ActivateCVCmd.txt"
    f = open(filename, 'w')
    
    Appfilename = 'KIOSKIII_2013.bin'
    path =  sys.path[0]  
    
    #-- 1. calulate file data hash in fHash(32 bytes) -------------------
    intHash = sha256_IDT(path +'\\'+ Appfilename, Appfilename)
    print(hex(intHash))

    #-- 2. encrypte hash by firmware private key (256 bytes) ----
    plaintData = intHash

    fname = path + "\\Firm_private_d.txt"
    d = GetDataFromFile(fname)

    fname = path + "\\Firm_N.txt"
    n = GetDataFromFile(fname)

    encryptedData = my_RSA_encrypt(plaintData, d, n)
    WriteCommandActivateCheckValue(f, encryptedData)
    
    return  
 
 #---------- SHA256-----------------
# return value:
#    fMidHash: int, 32 bytes
def sha256_IDT_test(filename, onlyname):
    f = open(filename, 'rb')
    fdata = f.read() #type of fdata is str
    
    fMidHash = 0
    print(hex(len(fdata)))
    for i in range(0, len(fdata)/256):
      fMidData = fdata[i*256:i*256+256]
      sh = hashlib.sha256()
      sh.update(fMidData)
      hexdigest = sh.hexdigest()
      fMidHash = fMidHash ^ int(hexdigest, 16)
    hashf = open('hash.txt', 'w')
    hashf.write(hex(fMidHash))
    hashf.close()
    #print (hex(fMidHash),"*",onlyname )
  
    f.close()
    return fMidHash  # type int
       
def test():
    filename = "KIOSKIII_2013.bin"
    sha256_IDT_test(filename, filename)
    return

def main():
    Do()
    GetActivateCVCommand()
    #test()
    
    return    
    
    
        
#-- main --
main()