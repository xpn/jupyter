import os
import re
from struct import unpack

# Huge thanks to https://github.com/Sentinel-One/CobaltStrikeParser/blob/master/parse_beacon_config.py

CONFIG_SIGNATURE = b'\x2e\x2f\x2e\x2f\x2e\x2c'
CONFIG_XOR_KEY = 0x2e
MALLEABLE_CONFIG_SIZE = 4096
TYPE_NONE = 0
TYPE_SHORT = 1
TYPE_INT = 2
TYPE_STR = 3

def typeDisplay(arg):
  if arg == 0x0:
    return "HTTP"
  elif arg == 0x1:
    return "HTTP/DNS"
  elif arg == 0x2:
    return "SMB"
  elif arg == 0x4:
    return "TCP"
  elif arg == 0x8:
    return "HTTPS"
  elif arg == 0x10:
    return "TCP"
  else:
    return "UNKNOWN"

def proxyDisplay(arg):
  if arg == 0x1:
    return "Use direct connection"
  elif arg == 0x2:
    return "Use IE settings"
  elif arg == 0x4:
    return "Use proxy server in options"
  else:
    return "Unknown Value"

def boolDisplay(arg):
  if arg == 0:
    return "false"
  elif arg == 1:
    return "true"
  else:
    return "unknown"

def dateDisplay(arg):
  if arg == 0:
    return "None"
  
  date = str(arg)
  return "%s-%s-%s" % (date[0:4], date[4:6], date[6:])

OPTION_INFO = [
  (""),                                 #0
  ("Type", typeDisplay),                #1
  ("Port"),                             #2
  ("Polling"),                          #3
  ("Unknown"),                          #4
  ("Jitter"),                           #5
  ("MaxDNS"),                           #6
  ("PublicKey"),                        #7
  ("C2Server"),                         #8
  ("UserAgent"),                        #9
  ("Path"),                             #10
  ("Unknown3"),                         #11
  ("Header1"),                          #12
  ("Header2"),                          #13
  ("Injection Target"),                 #14
  ("PipeName"),                         #15
  ("Year"),                             #16
  ("Month"),                            #17
  ("Day"),                              #18
  ("DNS_idle"),                         #19
  ("DNS_sleep"),                        #20
  ("SSH_host"),                         #21
  ("SSH_port"),                         #22
  ("SSH_username"),                     #23
  ("SSH_password"),                     #24
  ("SSH_publickey"),                    #25
  ("Method1"),                          #26
  ("Method2"),                          #27
  ("Chunked"),                          #28
  ("Spawnto_x86"),                      #29
  ("Spawnto_x64"),                      #30
  ("Unknown5"),                         #31
  ("Proxy_HostName"),                   #32
  ("Proxy_UserName"),                   #33
  ("Proxy_Password"),                   #34
  ("Proxy_Access", proxyDisplay),       #35
  ("create_remote_thread"),             #36
  ("Watermark"),                        #37
  ("StageCleanup", boolDisplay),        #38
  ("CFGCaution", boolDisplay),          #39
  ("KillDate", dateDisplay),            #40
  (""),                                 #41
  ("ObfuscateSectionsInfo"),            #42
  ("ProcInject_StartRWX", boolDisplay), #43
  ("ProcInject_UseRWX", boolDisplay),   #44
  ("ProcInject_MinAllocSize"),          #45
  ("ProcInject_PrependAppend_x86"),     #46
  ("ProcInject_PrependAppend_x64"),     #47
  (""),                                 #48
  (""),                                 #49
  ("UsesCookies", boolDisplay),         #50
  ("ProcInject_Execute"),               #51
  ("ProcInject_AllocationMethod"),      #52
  ("ProcInject_Stub"),                  #53
  ("HostHeader")                        #54
]

class CobaltStrikeOption:
  def __init__(self, data):
    self.data = data

  def _parseString(self, data):
    try:
      return data[:data.index(b'\0', 0)]
    except:
      return b''

  def parse(self):

    (self.id,self.type,self.length) = unpack(">HHH", self.data[:6])
    func = None

    if self.id >= len(OPTION_INFO) or OPTION_INFO[self.id] == "":
      name = f"<{self.id}>"
      func = None
    elif len(OPTION_INFO[self.id]) == 2:
      name = OPTION_INFO[self.id][0]
      func = OPTION_INFO[self.id][1]
    else:
      name = OPTION_INFO[self.id]
      func = None

    if self.type == TYPE_SHORT:
      data = unpack(">H", self.data[6:8])
      if func != None:
        desc = func(data[0])
      else:
        desc = data[0]
      return (name,desc)

    elif self.type == TYPE_INT:
      data = unpack(">I", self.data[6:10])
      if func != None:
        desc = func(data[0])
      else:
        desc = data[0]
      return (name,desc)
      
    elif self.type == TYPE_STR:
      data = unpack("{}s".format(self.length), self.data[6:6+self.length])
      if func != None:
        desc = func(data[0])
      else:
        desc = self._parseString(data[0])
      return (name,desc)
    else:
      return ()

  def nextOffset(self):
    return unpack(">H", self.data[4:6])[0]

class CobaltStrike:

  def __init__(self, data):
    self.data = data

  @staticmethod
  def decodeConfig(cfg_blob):
    return bytes([cfg_offset ^ CONFIG_XOR_KEY for cfg_offset in cfg_blob])

  def readConfig(self):
    encoded = re.search(CONFIG_SIGNATURE, self.data)
    if not encoded:
      return None

    # We need to un'xor 
    decoded = CobaltStrike.decodeConfig(self.data[encoded.start():encoded.start()+MALLEABLE_CONFIG_SIZE])

    offset = 0
    retData = []
    while offset < MALLEABLE_CONFIG_SIZE:
      config = CobaltStrikeOption(decoded[offset:])
      retData.append(config.parse())
      offset += 6 + config.nextOffset()
    
    return retData

if __name__ == "__main__":
  with open("cs.bin", "rb") as fd:
    data = fd.read()
    CobaltStrike(data).readConfig()