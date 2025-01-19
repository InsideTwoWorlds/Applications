import socketserver
import struct
import zlib
import re

_DATA_PATH = './Playerdata.bin'

_32bit = 0xFFFFFFFF
_8bit = 0xFF
_G64_BASE = bytes([
    0xD2, 0x12, 0x13, 0xD3, 0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 
    0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 
    0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 
    0x3E, 0xFE, 0xFA, 0x3A, 0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 
    0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 
    0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 
    0x27, 0xE7, 0xE6, 0x26])

def _saveData(data):
    with open(_DATA_PATH, 'wb') as f:
        f.write(data)
def _loadData():
    try:
        with open(_DATA_PATH, 'rb') as f:
            return f.read()
    except:
        return b''
    
def makeDstr(text):
    text = text.encode("ascii")
    textlen = len(text)
    return struct.pack("<I{}s".format(textlen), textlen, text)
def parseDstr(data, off):
    [strlen] = struct.unpack("<I", data[off:off+4])
    off+= 4 + strlen
    text = data[off-strlen: off].decode()
    return text, off
def _server_info_packet():
    nm = '+"LocalHost""TWMP2;10.0.0.5"'
    dets = struct.pack("<I",0) + makeDstr(nm)
    cdets = zlib.compress(dets)
    return struct.pack("<I",len(cdets)+4) + cdets
def _step(num):
    return (num*0x343FD + 0x269EC3)&_32bit
def gen64(combined):
    out = bytearray(0x40)
    ebp = edi = tmp = 0
    for b in combined:
        edi+= b+tmp
        tmp^= b
        ebp+= tmp
    for i in range(0x40):
        res = combined[(ebp+i)%8]
        out[i] = res^_G64_BASE[(edi+i)%0x40]
    rg = edi+ebp
    for i in range(0x40):
        rg = _step(rg)
        out[i]^= (rg>>0x10)&_8bit
    for i in range(0x20):
        rg = _step(rg)
        sA = (rg>>0x10)%0x40
        rg = _step(rg)
        sB = (rg>>0x10)%0x40
        (out[sA], out[sB]) = (out[sB], out[sA])
    return bytes(out)
def _init_error():
    msg = ''
    err = struct.pack('<I',0)
    dets = b''.join([err, makeDstr(msg)])
    cdets = zlib.compress(dets)
    packlen = struct.pack("<I",len(cdets)+4)
    return packlen+cdets

def _server_welcome_packet(serial):
    txt1 = 'Solo Server'
    txt2 = '<0xFF0000FF><F2>Solo Offline Server<break=10.0>\r\n'
    unkA = bytes([0,0,0,0, 0x55, 0xa6, 0xd8, 0x3b])
    unkB = bytes([0]*49) #no clue wtf these do
    unkB+= gen64(serial)
    seed = 0
    grp = _grp(seed)
    unkB+= struct.pack('<6I',0,seed,*grp)#TODO
    dets = b''.join([unkA, makeDstr(txt1), makeDstr(txt2), unkB])
    cdets = zlib.compress(dets)
    packlen = struct.pack("<I",len(cdets)+4)
    return packlen+cdets
def _grp(seed=0):
    #not sure if it matters, should generate from seed? seems fine
    return (1153721648,409151997,1543387035,1810309313)
def _chnl(name, index):
    return f'{name}#translate{name}_Channel_{index:02d}'
_CHANNELS_ = [
        (_chnl("Net_T_01",1), 0,1,0,0),
        (_chnl("Net_T_02",1), 0,1,0,0),
        (_chnl("Net_T_03",1), 0,1,0,0),
        (_chnl("Net_T_04",1), 0,1,0,0),
    ]
def enumerateChannelData():
    chunks = []
    for (channelName, curPlayers, maxPlayers, gA, gB) in _CHANNELS_:
        chunks.append(f'$gamechannel "{channelName}" "{curPlayers}" "{maxPlayers}" "{gA}" "{gB}"'.encode("ascii"))
    return b"\0".join(chunks)+b"\0"
def joinChatandEnumerate():
    chunks = []
    chunks.append(b'/joinchatchannel "translateNetCityMainChannel" "" "1"')
    chunks.append(b'$chatchannel "translateNetCityMainChannel" "" "1"')
    return b"\0".join(chunks)+b"\0"

_getPD = re.compile(r'/getplayerdata "(.+)" "TwoWorlds.1.0"')
_setPD = re.compile(r'/setplayerdata ".+" "TwoWorlds.1.0" "(\d+)" "\d+" "\d+"')
_leaveGameC = re.compile(r'/leavegamechannel "1"')
_reqJoinGameC = re.compile(r'/requestjoingamechannel "(.+)"')
_joinGameC = re.compile(r'/joingamechannel "(.+)" "(.+)"')
_reqCreateGame = re.compile(r'/requestcreategame "(.+)"')
_getGRP = re.compile(r'/getguildrankpoints')

class ConnectionHandler(socketserver.BaseRequestHandler):
    def handlePacket(self, cmd):
        #print(cmd)
        if m := _getPD.match(cmd):
            playerdata = _loadData()
            pdl = len(playerdata)
            if pdl:
                print(f'Playerdata loaded {pdl}bytes')
            rescmd = f'/getplayerdata "{m.group(1)}" "TwoWorlds.1.0" {pdl}\0'
            self.request.sendall(b''.join([rescmd.encode('ascii'), playerdata]))
        elif m := _setPD.match(cmd):
            pdl = int(m.group(1))
            playerdata = self.getData(pdl)
            _saveData(playerdata)
            print(f'Playerdata saved {pdl}bytes')
        elif m := _leaveGameC.match(cmd):
            self.request.sendall(enumerateChannelData())
        elif m := _reqJoinGameC.match(cmd):
            rescmd = f'/requestjoingamechannel "{m.group(1)}" "1"\0'
            self.request.sendall(rescmd.encode('ascii'))
        elif m := _joinGameC.match(cmd):
            rescmd = f'/joingamechannel "{m.group(1)}" "1"\0'
            self.request.sendall(rescmd.encode('ascii'))
            self.request.sendall(joinChatandEnumerate())
        elif m := _reqCreateGame.match(cmd):
            rescmd = f'/creategame "{m.group(1)}"\0'
            self.request.sendall(rescmd.encode('ascii'))
        elif m := _getGRP.match(cmd):
            (a,b,c,d) = _grp()
            rescmd = f'/getguildrankpoints "{a}" "{b}" "{c}" "{d}"\0'.encode('ascii')
            self.request.sendall(rescmd)
        #else: #UNIMPLEMENTED, probably not needed for solo.
            #print('NOT IMPLEMENTED:', cmd)
    def setup(self):
        self.data = b''
        self.SK = bytearray(struct.pack('<II', 0xA6AE1F9B, 0x438DFF40))
    def handle(self):
        #Handshake - AcceptAny
        LIS = 2
        while LIS:
            while(len(self.data)<4):
                self.data+= self.request.recv(2048)
            pack_len = struct.unpack("<I",self.data[0:4])[0]
            while(len(self.data)<pack_len):
                data+= self.request.recv(2048)
            res = zlib.decompress(self.data[4:])
            self.data = self.data[pack_len:]
            if LIS == 2:
                #skip 16
                langname, off = parseDstr(res, 16)
                RK = res[off+8:off+16]
                for i in range(len(RK)):
                    self.SK[i]^=RK[i]
                self.request.sendall(_server_info_packet())
                LIS = 1
            elif LIS == 1:
                username, off = parseDstr(res, 0)
                password, off = parseDstr(res, off)
                if username and password:
                    self.request.sendall(_server_welcome_packet(bytes(self.SK)))
                    LIS = 0
                else:
                    self.request.sendall(_init_error())
        #LOGIN SUCCESS
        print('Player Connected')
        while True:
            self.data+= self.request.recv(2048)
            if not self.data:
                print('Player disconnected')
                print('Close this window to close the server')
                break
            while self.data:
                #check for loose data and discard
                if (len(self.data)>2 and
                        self.data[0]==0x78 and
                        self.data[1]==0x9c):
                    dcmp = zlib.decompressobj()
                    dcmp.decompress(self.data)
                    while not dcmp.eof:
                        cdat = self.request.recv(2048)
                        dcmp.decompress(cdat)
                    self.data = dcmp.unused_data
                    continue
                #parse commands
                try:
                    cmd_l = self.data.index(0)
                except:
                    print(self.data)
                    continue
                cmd = self.data[0:cmd_l].decode()
                self.data = self.data[cmd_l+1:]
                if cmd:
                    self.handlePacket(cmd)
    def getData(self, ln):
        while len(self.data)<ln:
            self.data+= self.request.recv(2048)
        dat = self.data[0:ln]
        self.data = self.data[ln:]
        return dat

if __name__ == "__main__":
    HOST, PORT = "localhost", 17171

    with socketserver.TCPServer((HOST, PORT), ConnectionHandler) as server:
        print('Connect to 127.0.0.1')
        print('Close this window to close the server')
        server.serve_forever()
