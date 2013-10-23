#TSParser

TSParser is a Python script used to parse MPEG-2 TS stream.

##DESCRIPTION


You can retrieve the following information by this script.

    PSI
        PMT (Program Map Table)
        SIT (Selection Information Table)
        PAT (Program Association Table)
    PCR (Program Clock Reference)
    ES (Elementary Stream)

You can print out PMT, ES and SIT information by specified PID, or by searching. For searching mode, you can print out all specified table packets, or only unique table packets.

For ES packet, the PES ( Packetized Elementary Stream) header is also printed out. By these information, you can find the start pointer of GOP (Group Of Pictures) or I-pictures.

Three types of packet size (188 bytes,192 bytes, 204 bytes) TS stream can be handled by this script. 

##USAGE

 TSParser.py -t <188|192|204> -m PAT    
 TSParser.py -t <188|192|204> -m <PMT|ES|SIT> PID    
 TSParser.py -s PCR     
 TSParser.py -s <PAT|PMT|SIT> --all     
 TSParser.py -s <PAT|PMT|SIT> --unique'''

 Example: TSParser.py -t 188 -m PMT 1fc8

###Options:

* -h, --help  
      Show this help message and exit.

* -t PACKET_SIZE, --type=PACKET_SIZE  
      Specify TS packet size[188, 192, 204], default = 188.

* -m MODE, --mode=MODE  
      Specify parsing mode[PAT, PMT, SIT, ES], default = PAT.

* -s SEARCHITEM, --search=SEARCHITEM  
      Search PAT/PMT/PCR/SIT packets and output Information.

* --all  
      Output all PAT/PMT/SIT packets Information. default,only the first one is output.

* --unique  
      Output unique PAT/PMT/SIT packets Information.default, only the first one is output.

##AUTHOR  
      guo.zhaohui@gmail.com

