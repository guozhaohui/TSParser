#! /usr/bin/python
# -*- coding: cp932 -*-

#this script is used to parse MPEG-2 TS stream
#
#Author: Zhaohui Guo (guo.zhaohui@gmail.com)
#Copyright(c)2009 Zhaohui GUO

"""this script is used to parse MPEG-2 TS stream.

204-bytes TS stream for JIMAKU-test can be processed.
"""

import struct
import Tkinter
import tkMessageBox
import tkFileDialog
import sys
from optparse import OptionParser

class SystemClock:
    def __init__(self):
        self.PCR_base_hi = 0x0
        self.PCR_base_lo = 0x0
        self.PCR_extension = 0x0
    def setPCR(self, PCR_base_hi, PCR_base_lo, PCR_extension):
        self.PCR_base_hi = PCR_base_hi
        self.PCR_base_lo = PCR_base_lo
        self.PCR_extension = PCR_extension
    def getPCR(self):
        return self.PCR_base_hi, self.PCR_base_lo, self.PCR_extension

class PESPacketInfo:
    def __init__(self):
        self.PTS_hi = 0
        self.PTS_lo = 0
        self.streamID = 0
        self.AUType = ""
    def setPTS(self, PTS_hi, PTS_lo):
        self.PTS_hi = PTS_hi
        self.PTS_lo = PTS_lo
    def getPTS(self):
        return self.PTS_hi, self.PTS_lo
    def setStreamID(self, streamID):
        self.streamID = streamID
    def setAUType(self, auType):
        self.AUType = auType
    def getStreamID(self):
        return self.streamID
    def getAUType(self):
        return self.AUType
       

def readFile(filehandle, startPos, width):
    filehandle.seek(startPos,0)
    if width == 4:
        string = filehandle.read(4)
        if string == '':
            raise IOError
        return struct.unpack('>L',string[:4])[0]
    elif width == 2:
        string = filehandle.read(2)
        if string == '':
            raise IOError
        return struct.unpack('>H',string[:2])[0]
    elif width == 1:
        string = filehandle.read(1)
        if string == '':
            raise IOError
        return struct.unpack('>B',string[:1])[0]

def parseAdaptation_Field(filehandle, startPos,PCR):
    n = startPos
    adaptation_field_length = readFile(filehandle,n,1)
    if adaptation_field_length > 0:
        flags = readFile(filehandle,n+1,1)
        PCR_flag = (flags>>4)&0x1
        if PCR_flag == 1:
            PCR1 = readFile(filehandle,n+2,4)
            PCR2 = readFile(filehandle,n+6,2)
            PCR_base_hi = (PCR1>>31)&0x1
            PCR_base_lo = (PCR1<<1)+ ((PCR2>>15)&0x1)
            PCR_ext = PCR2&0x1FF
            PCR.setPCR(PCR_base_hi, PCR_base_lo, PCR_ext)
##            print 'Found PCR in Adaptation field, PCR_base = hi:0x%X  lo:0x%X  PCR_ext = 0x%X' %(PCR_base_hi, PCR_base_lo, PCR_ext)
    return adaptation_field_length + 1

def getPTS(filehandle, startPos):
    n = startPos
    time1 = readFile(filehandle,n,1)
    time2 = readFile(filehandle,n+1,2)
    time3 = readFile(filehandle,n+3,2)
    PTS_hi = (time1>>3)&0x1
    PTS_low = ((time1>>1)&0x3)<<30
    PTS_low += ((time2>>1)&0x7FFF)<<15
    PTS_low += ((time3>>1)&0x7FFF)

    return PTS_hi, PTS_low

def parseIndividualPESPayload(filehandle, startPos):

    n = startPos

##    local1 = readFile(filehandle,n,4)
##    local2 = readFile(filehandle,n+4,4)
##    local3 = readFile(filehandle,n+8,4)
##    print 'NAL header = 0x%08X%08X%08X' %(local1,local2,local3)

    local = readFile(filehandle,n,4)
    k = 0
    while((local&0xFFFFFF00) != 0x00000100):
        k += 1;
        if (k > 100):
            return "Unknown AU type"
        local = readFile(filehandle,n+k,4)       
   

    if(((local&0xFFFFFF00) == 0x00000100)&(local&0x1F == 0x9)):
        primary_pic_type = readFile(filehandle,n+k+4,1)
        primary_pic_type = (primary_pic_type&0xE0)>>5
        if (primary_pic_type == 0x0):
            return "IDR_picture"
        else:
            return "non_IDR_picture"
 

def parsePESHeader(filehandle, startPos,PESPktInfo):
    n = startPos
    stream_ID = readFile(filehandle, n+3, 1)
    PES_packetLength = readFile(filehandle, n+4, 2)
    PESPktInfo.setStreamID(stream_ID)

    k = 6   
      
    if ((stream_ID != 0xBC)& \
             (stream_ID != 0xBE)& \
             (stream_ID != 0xF0)& \
             (stream_ID != 0xF1)& \
             (stream_ID != 0xFF)& \
             (stream_ID != 0xF9)& \
             (stream_ID != 0xF8)):
            
        PES_packet_flags = readFile(filehandle, n+5, 4)
        PTS_DTS_flag = ((PES_packet_flags>>14)&0x3)
        PES_header_data_length = PES_packet_flags&0xFF

        k += PES_header_data_length + 3

        if (PTS_DTS_flag == 0x2):
            (PTS_hi, PTS_low) =  getPTS(filehandle, n+9)
##            print 'PTS_hi = 0x%X, PTS_low = 0x%X' %(PTS_hi, PTS_low)
            PESPktInfo.setPTS(PTS_hi, PTS_low)
           
        elif (PTS_DTS_flag == 0x3):
            (PTS_hi, PTS_low) =  getPTS(filehandle, n+9)
##            print 'PTS_hi = 0x%X, PTS_low = 0x%X' %(PTS_hi, PTS_low)
            PESPktInfo.setPTS(PTS_hi, PTS_low)

            (DTS_hi, DTS_low) =  getPTS(filehandle, n+14)
##            print 'DTS_hi = 0x%X, DTS_low = 0x%X' %(DTS_hi, DTS_low)
    else:
        k = k
        return       

    auType = parseIndividualPESPayload(filehandle, n+k)
    PESPktInfo.setAUType(auType)
       
def parsePATSection(filehandle, k):

    local = readFile(filehandle,k,4)

    table_id = (local>>24)
    if (table_id != 0x0):
        print 'Ooops! error in parsePATSection()!'
        return

    section_length = (local>>8)&0xFFF
    print 'section_length = %d' %section_length

    transport_stream_id = (local&0xFF) << 8;
   
    local = readFile(filehandle, k+4, 4)

    transport_stream_id += (local>>24)&0xFF
   
    transport_stream_id = (local >> 16)
    version_number =  (local>>17)&0x1F
    current_next_indicator = (local>>16)&0x1
    section_number = (local>>8)&0xFF
    last_section_number = local&0xFF;
    print 'section_number = %d, last_section_number = %d' %(section_number, last_section_number)

    length = section_length - 4 - 5
    j = k + 8

    while (length > 0):
        local =  readFile(filehandle, j, 4)
        program_number = (local >> 16)
        program_map_PID = local & 0x1FFF
        print 'program_number = 0x%X' %program_number
        if (program_number == 0):
            print 'network_PID = 0x%X' %program_map_PID
        else:
            print 'program_map_PID = 0x%X' %program_map_PID
        length = length - 4;

       
   
def parsePMTSection(filehandle, k):
   
    local = readFile(filehandle,k,4)

    table_id = (local>>24)
    if (table_id != 0x2):
        print 'Ooops! error in parsePATSection()!'
        return

    section_length = (local>>8)&0xFFF
    print 'section_length = %d' %section_length

    transport_stream_id = (local&0xFF) << 8;
   
    local = readFile(filehandle, k+4, 4)

    transport_stream_id += (local>>24)&0xFF
   
    transport_stream_id = (local >> 16)
    version_number =  (local>>17)&0x1F
    current_next_indicator = (local>>16)&0x1
    section_number = (local>>8)&0xFF
    last_section_number = local&0xFF;
    print 'section_number = %d, last_section_number = %d' %(section_number, last_section_number)

    local = readFile(filehandle, k+8, 4)
   

    PCR_PID = (local>>16)&0x1FFF
    print 'PCR_PID = 0x%X' %PCR_PID
    program_info_length = (local&0xFFF)

    j = k + 12 + program_info_length
    length = section_length - 4 - 9 - program_info_length

    while (length > 0):
        local1 = readFile(filehandle, j, 1)
        local2 = readFile(filehandle, j+1, 4)

        stream_type = local1;
        elementary_PID = (local2>>16)&0x1FFF
        ES_info_length = local2&0xFFF

        print 'stream_type = 0x%X, elementary_PID = 0x%X, ES_info_length = %d' %(stream_type, elementary_PID, ES_info_length)

       
        j += 5 + ES_info_length
        length -= 5 + ES_info_length

   
   
           
def parseTSMain(filehandle, packet_size, mode, pid):

    PCR = SystemClock()
    PESPktInfo = PESPacketInfo()

    if (packet_size != 192):
        n = 0
    else:
        n = 4
       
    packetCount = 0
    rdi_count = 0

    EntryPESPacketNumList = []

    idr_flag = False
    last_SameES_packetNo = 0
    last_EntryTPI = 0


    try:
        while(True):

            if (rdi_count == 0):
                packetCount += 1
                rdi_count += 1
           
            PacketHeader = readFile(filehandle,n,4)
           
            syncByte = (PacketHeader>>24)
            if (syncByte != 0x47):
                print 'Ooops! Can NOT found Sync_Byte! maybe something wrong with the file'
                break

            payload_unit_start_indicator = (PacketHeader>>22)&0x1
           
            PID = ((PacketHeader>>8)&0x1FFF)
##            if (PID == 0x0):
##                print 'Found PAT Packet! packet No. %d' %packetCount
##                print 'payload_unit_start_indicator = %d' %payload_unit_start_indicator      
 
               
            adaptation_fieldc_trl = ((PacketHeader>>4)&0x3)
            Adaptation_Field_Length = 0

            if (adaptation_fieldc_trl == 0x2)|(adaptation_fieldc_trl == 0x3):
                Adaptation_Field_Length = parseAdaptation_Field(filehandle,n+4,PCR)


            if (adaptation_fieldc_trl == 0x1)|(adaptation_fieldc_trl == 0x3):

                PESstartCode = readFile(filehandle,n+Adaptation_Field_Length+4,4)
               
                if ((PESstartCode&0xFFFFFF00) == 0x00000100)& \
                   (PID == pid)&(payload_unit_start_indicator == 1):
                   
                    parsePESHeader(filehandle, n+Adaptation_Field_Length+4, PESPktInfo)

                    if (mode == 'ES'):
                        print 'packet No. %d,  ES PID = 0x%X,  Steam_ID = 0x%X,  AU_Type = %s' \
                        %(packetCount, PID, PESPktInfo.getStreamID(), PESPktInfo.getAUType())

                        if (idr_flag == True):
                            EntryPESPacketNumList.append(last_SameES_packetNo - last_EntryTPI +1)
                           
                           
                        if (PESPktInfo.getAUType() == "IDR_picture"):
                            idr_flag = True
                            last_EntryTPI = packetCount
                        else:
                            idr_flag = False
                       
                   
                                                           

                elif (((PESstartCode&0xFFFFFF00) != 0x00000100)& \
                      (payload_unit_start_indicator == 1)):

                    pointer_field = (PESstartCode >> 24)
                    table_id = readFile(filehandle,n+Adaptation_Field_Length+4+1+pointer_field,1)

                    if ((table_id == 0x0)&(PID != 0x0)):
                        print 'Ooops!, Something wrong in packet No. %d' %packetCount

                    k = n+Adaptation_Field_Length+4+1+pointer_field

                    if (table_id == 0x0):
                        packetCount -= 1
                        rdi_count -= 1
                        if (mode == 'PAT'):
                            print 'pasing PAT Packet! packet No. %d' %packetCount
                            parsePATSection(filehandle, k)
                            return
                       
                    elif (table_id == 0x2):
                        packetCount -= 1
                        rdi_count -= 1
                        if ((mode == 'PMT')&(PID == pid)):
                            print 'pasing PMT Packet! packet No. %d, PID = 0x%X' %(packetCount, PID)
                            parsePMTSection(filehandle, k)
                            return
                    else:
                        print "Unknown PSI!"


                if (PID == pid):
                    last_SameES_packetNo = packetCount
                   
                   
               
##          skip to next TS packet and increase packet count by 1.
            n += packet_size

            packetCount += 1
            rdi_count += 1
           
            if (rdi_count == 32):
                rdi_count = 0


##          whether the maxim packet number reached?
            if (packetCount > 1450000):
                break
           
    except IOError:
        print 'IO error! maybe reached EOF'
    else:
        filehandle.close()

    print '================================================\n'
    for x in EntryPESPacketNumList:
        print hex(x)


def getFilename():   
    root=Tkinter.Tk()
    fTyp=[('.ts File','*.ts'),('.TOD File','*.TOD'),('.trp File','*.trp'),('All Files','*.*')]
    iDir='C:/'
    filename=tkFileDialog.askopenfilename(filetypes=fTyp,initialdir=iDir)
    root.destroy()
    return filename;

def Main():
 
    usage = "\n\t%TSParser -t <188|192|204> -m PAT\
    \n\t%TSParser -t <188|192|204> -m PMT PID\
    \n\t%TSParser -t <188|192|204> -m ES PID\n\n \
    Example: TSParser -t 188 -m PMT 1fc8"
   
    cml_parser = OptionParser(usage=usage)
    cml_parser.add_option("-t", "--type", action="store", type="int", dest="packet_size", default="188",
                          help="specify TS packet size, default = 188")

    cml_parser.add_option("-m", "--mode", action="store", type="string", dest="mode", default="PAT",
                          help="specify parsing mode, default = PAT")


    (opts, args) = cml_parser.parse_args(sys.argv)

    if ((opts.mode != "PAT") & (len(args) < 2)):
        cml_parser.print_help()
        return

    if (opts.mode != "PAT"):
        pid = int(args[1], 16)
    else:
        pid = 0;
 
    filename = getFilename()
    if (filename == ""):
        return
    print filename
    filehandle = open(filename,'rb')

    parseTSMain(filehandle, opts.packet_size, opts.mode, pid)

   
if __name__ == "__main__":
   
    Main()
   
