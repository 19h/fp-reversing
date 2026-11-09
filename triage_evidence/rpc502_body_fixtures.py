"""Declared byte fixtures for source parser recovery;no authentication claim."""
def tlv(tag,b):
 assert 0<=tag<256
 n=len(b);size=bytes([n])if n<128 else bytes([0x80+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big');return bytes([tag])+size+b

def certificate(name=b'Fixture',version=True,oid_last=5,serial=b'\x01',modulus_bytes=128):
 seq=lambda b:tlv(0x30,b)
 oid=lambda b:tlv(6,b)
 integer=lambda b:tlv(2,b)
 algorithm=seq(oid(bytes.fromhex('2a864886f70d0101')+bytes([oid_last]))+tlv(5,b''))
 name=seq(tlv(0x31,seq(oid(bytes.fromhex('550403'))+tlv(0x13,name))))if name is not None else seq(b'')
 validity=seq(tlv(0x17,b'260101000000Z')+tlv(0x17,b'270101000000Z'))
 rsa=seq(integer(b'\x00\xc1'+bytes([0x55])*(modulus_bytes-1))+integer(bytes.fromhex('010001')))
 pubkey=seq(seq(oid(bytes.fromhex('2a864886f70d010101'))+tlv(5,b''))+tlv(3,b'\x00'+rsa))
 tbs=seq((tlv(0xa0,integer(b'\x02'))if version else b'')+integer(serial)+algorithm+name+validity+name+pubkey)
 return seq(tbs+algorithm+tlv(3,b'\x00'+bytes(modulus_bytes)))
