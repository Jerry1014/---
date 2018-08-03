# -*- coding: utf-8 -*-
class Separator:
    data: str

    def __init__(self, indata):
        self.data = indata
        self.protocols = []
        
    def separate(self):
        data_length = len(self.data)
        for i in range(data_length):
            # 帧起始符
            if self.data[i] == '7' and self.data[i+1] == 'F':
                i += 2
                item = i
                protocol = {'HEAD': '7F'}
                try:
                    # 帧长度域
                    if int(self.data[item], 16) > 7:
                        # 拓展帧长度
                        protocol['LENL'] = 1
                        protocol['LEN0'] = self.data[item:item+2]
                        protocol['LEN1'] = self.data[item+2:item+4]
                        item += 4
                    else:
                        # 非拓展帧长度
                        protocol['LENL'] = 0
                        protocol['LEN0'] = self.data[item:item+2]
                        item += 2

                    # 控制码域
                    ctr_num = 0
                    ctrn = 'CTR' + str(ctr_num)
                    protocol[ctrn] = self.data[item:item+2]
                    item += 2

                    while int(protocol[ctrn][0], 16) < 8:
                        ctr_num += 1
                        ctrn = 'CTR' + str(ctr_num)
                        protocol[ctrn] = self.data[item:item+2]
                        item += 2
                    protocol['CTRL'] = ctr_num

                    # 帧长度原码反码判断
                    if int(self.hex_all(bin(int(protocol['CTR0'][0], 16)))[3], 2) == 1:
                        if protocol['LENL'] == 1:
                            protocol_len = (int(protocol['LEN0'][0], 16) - 8 + int(protocol['LEN1'][0], 16)) * 2**4 + \
                                           int(protocol['LEN0'][1], 16) + int(protocol['LEN1'][1], 16) - 2
                            protocol_len_tem = protocol_len + 3
                        else:
                            protocol_len = int(protocol['LEN0'][0], 16) * 2**4 + int(protocol['LEN0'][1], 16) - 1
                            protocol_len_tem = protocol_len + 2
                    else:
                        if protocol['LENL'] == 1:
                            protocol_len = ~(int(protocol['LEN0'][0], 16) * 2**4 + int(protocol['LEN0'][1], 16)) +\
                                           ~(int(protocol['LEN1'][0], 16) * 2**4 + int(protocol['LEN1'][1], 16)) - 2
                            protocol_len_tem = protocol_len + 3
                        else:
                            protocol_len = ~((int(protocol['LEN0'][0], 16) - 8) * 2**4 +
                                               int(protocol['LEN0'][1], 16)) - 1
                            protocol_len_tem = protocol_len + 2

                    protocol_len -= protocol['CTRL'] + 1
                    # 多级地址域
                    if int(self.hex_all(bin(int(protocol['CTR0'][0], 16)))[4], 2) == 0:
                        protocol['MAM'] = self.data[item:item + 2]
                        if int(self.hex_all(bin(int(protocol['CTR0'][0], 16)))[2], 2) == 1:
                            mam_gl = int(self.hex_all(bin(int(protocol['MAM'][1], 16)))[-3:], 2) - \
                                     int(self.hex_all(bin(int(protocol['MAM'][0], 16)))[-3:], 2) + 1
                        else:
                            mam_gl = int(self.hex_all(bin(int(protocol['MAM'][1], 16)))[-3:], 2)
                        item += 2
                        protocol_len -= 1
                    else:
                        protocol['MAM'] = None

                    # 地址域
                    addresing = int(self.hex_all(bin(int(protocol['CTR0'][1], 16)))[-3:], 2)
                    if addresing == 7:
                        protocol['ADDRES'] = 0
                        protocol['ADD'] = None
                    elif addresing == 6:
                        protocol['ADDRES'] = 1
                        protocol['ADD'] = self.data[item:item+2]
                        item += 2
                        protocol_len -= 1
                    elif addresing == 5:
                        protocol['ADDRES'] = 2
                        protocol['ADD'] = self.data[item:item + 48]
                        item += 48
                        protocol_len -= 24
                    elif addresing == 4:
                        protocol['ADDRES'] = 3
                        if int(self.hex_all(bin(int(protocol['CTR0'][0], 16)))[4], 2) == 1:
                            protocol['ADD'] = self.data[item:item + 10]
                            item += 10
                            protocol_len -= 5
                        else:
                            protocol['ADD'] = self.data[item:item+mam_gl*10]
                            item += mam_gl * 10
                            protocol_len -= mam_gl * 5

                    # 帧序号域
                    protocol['SER'] = self.data[item:item+2]
                    item += 2
                    protocol_len -= 1

                    # 数据标识域
                    protocol['DI0'] = self.data[item:item+2]
                    item += 2
                    protocol_len -= 1
                    if (int(protocol['DI0'][0], 16)) > 11:
                        protocol['DIL'] = 1
                        protocol['DI1'] = self.data[item:item + 2]
                        item += 2
                        protocol_len -= 1
                    else:
                        protocol['DIL'] = 0

                    # 数据域
                    if protocol_len > 0:
                        protocol['DATA'] = self.data[item:item + protocol_len*2]
                        item = item + protocol_len * 2
                    else:
                        protocol['DATA'] = None

                    # 校验域
                    testcrc = self.crc16(self.data[i-2:item], protocol_len_tem)
                    protocol['CS'] = self.data[item:item + 4]
                    item += 4

                    if testcrc[2:4] == protocol['CS'][-2:] and testcrc[-2:] == protocol['CS'][0:2]:
                        self.protocols.append(protocol)
                        i = item - 1
                except Exception as e:
                    #print(e)
                    pass
                finally:
                    i += 1

    def crc16(self, testdata, data_len):
        crc = 0xFFFF
        if data_len == 0:
            data_len = 1
        t = 0
        while data_len != 0:
            crc ^= int(testdata[t:t + 2], 16)
            i = 0
            for i in range(8):
                if (crc & 1) == 1:
                    crc >>= 1;
                    crc ^= 0xA001
                else:
                    crc >>= 1;
                i += 1
            t += 2
            data_len -= 1
        return self.hex_all(hex(crc).upper())

    def hex_all(self, hex_part):
        if len(hex_part) < 6:
            hex_list = list(hex_part)
            while len(hex_list) < 6:
                hex_list.insert(2, '0')
            hex_part = "".join(hex_list)
        return hex_part


event = {'0100': '手报事件', '4001': '感温事件', '4002': '感烟事件', 'C0FF': '中心启动', '2401': '节点应答'}
inputdata = input()
result = Separator(inputdata)
result.separate()
print("共有%d个有效帧"%len(result.protocols))
for i in range(len(result.protocols)):
    try:
        print(event[result.protocols[i]['DATA'][0:4]])
    except KeyError:
        print("未知事件")
    print(result.protocols[i])

