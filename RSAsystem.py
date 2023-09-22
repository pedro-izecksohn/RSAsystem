from os import urandom
import math
import hashlib

def divisors (number):
    ret=[]
    if number<2:
        return ret
    while (number%2)==0:
        ret.append(2)
        number=number//2
    curdiv=3
    sqnpo=int(number**0.5)+1
    while curdiv < sqnpo:
        if (number%curdiv)==0:
            ret.append(curdiv)
            number = number//curdiv
        else:
            curdiv += 2
    if number!=1:
        ret.append(number)
    return ret

def isPrime(i):
    if (i<2) or ((i%2)==0):
        return False
    if (i==2) or (i==3):
        return True
    div=3
    sqipo=int(i**0.5)+1
    while div<sqipo:
        if (i%div)==0:
            return False
        div+=2
    return True

def haveCommon (l1, l2):
    for i in l1:
        if i in l2:
            return True
    return False

class PrivateKey:
    def __init__(self, n, d):
        self.n=n
        self.d=d
    def decrypt (self, lin):
        lout=[]
        dic={}
        for c in lin:
            print ("Now I'll decrypt a number.")
            if c in dic:
                lout.append(dic[c])
            else:
                m=pow(c,self.d,self.n)
                dic[c]=m
                lout.append(m)
        ret=""
        for i in lout:
            ret+=chr(i)
        return ret
    def encrypt (self, i:int):
        return pow(i,self.d,self.n)

def getD (e:int,totient:int):
    z=totient+1
    while (z%e)!=0:
        z+=totient
    d=z//e
    return d

class PublicKey:
    def __init__(self, n, e):
        self.n=n
        self.e=e
    def getPrivateKey (self):
        l=divisors(self.n)
        if len(l)!=2:
            raise Exception ("n has "+str(len(l))+" divisors.")
        p=l[0]
        q=l[1]
        totient=math.lcm (p-1, q-1)
        print ("totient="+str(totient))
        if (self.e<=1) or (self.e>=totient):
            raise Exception ("Invalid e.")
        d=getD(self.e,totient)
        print ("d="+str(d))
        return PrivateKey (self.n, d)
    def encrypt (self, s):
        ret=[]
        d={}
        for m in s:
            m=ord(m)
            if m in d:
                ret.append(d[m])
            else:
                c=pow(m,self.e,self.n)
                d[m]=c
                ret.append(c)
        return ret
    def decrypt (self, i:int):
        return pow(i,self.e,self.n)

class EncryptedMessage:
    def __init__(self,publicKey:PublicKey,plainText=None):
        self.publicKey=publicKey
        if plainText:
            self.encryptedMessage=publicKey.encrypt(plainText)
        else:
            self.encryptedMessage=None
    def __str__(self):
        return f"n={self.publicKey.n}\ne={self.publicKey.e}\n{self.encryptedMessage}"
    @classmethod
    def read(clazz,filename):
        file=open(filename,"r")
        n=None
        e=None
        for i in range(2):
            line=file.readline()
            l=line.split("=")
            if l[0]=="n":
                n=int(l[1])
            elif l[0]=="e":
                e=int(l[1])
        line=file.readline()
        file.close()
        line=line[1:-1]
        l=line.split(", ")
        l2=[]
        for s in l:
            l2.append(int(s))
        ret=clazz(PublicKey(n,e))
        ret.encryptedMessage=l2
        return ret
    def decrypt (self,key=None)->str:
        if key==None:
            key=self.publicKey.getPrivateKey()
        return key.decrypt(self.encryptedMessage)

class KeysPair:
    def __init__(self,n,e,d):
        self.n=n
        self.e=e
        self.d=d
    def __str__(self):
        return f"n={self.n}\ne={self.e}\nd={self.d}\n"
    @classmethod
    def read(clazz,filename):
        with open(filename,"r") as file:
            lines=file.readlines()
        n=None
        e=None
        d=None
        for line in lines:
            l=line.split("=")
            if l[0]=="n":
                n=int(l[1])
            elif l[0]=="e":
                e=int(l[1])
            elif l[0]=="d":
                d=int(l[1])
        return clazz(n,e,d)
    def getPublicKey (self):
        return PublicKey(self.n,self.e)
    def getPrivateKey (self):
        return PrivateKey(self.n,self.d)

def ba2int (ba):
    i=0
    for b in ba:
        i=(i*256)+b
    return i

class SignedMessage:
    def __init__(self,msg,obj,sig=None):
        self.msg=msg
        if type(obj)==KeysPair:
            kp=obj
            md5=hashlib.md5()
            md5.update(msg.encode("UTF-8"))
            h=ba2int(md5.digest())
            print(f'hash={h}')
            self.signature=kp.getPrivateKey().encrypt(h)
            print(f'signature={self.signature}')
            self.publicKey=kp.getPublicKey()
            if h>=self.publicKey.n:
                print("This key is too short.")
                exit()
        elif type(obj)==PublicKey:
            self.signature=sig
            self.publicKey=obj
    def verify(self):
        md5=hashlib.md5()
        md5.update(self.msg.encode("UTF-8"))
        h0=ba2int(md5.digest())
        print(f'h0={h0}')
        h1=self.publicKey.decrypt(self.signature)
        print(f'h1={h1}')
        return h0==h1
    def __str__(self):
        return f'#Begin signature:\n#n={self.publicKey.n}\n#e={self.publicKey.e}\n#signature={self.signature}\n#End signature.\n{self.msg}'
    @classmethod
    def read(clazz,filename):
        with open(filename,"r") as file:
            lines=file.readlines()
            if lines[0]!="#Begin signature:\n":
                print("Error: "+lines[0])
                return None
            l=lines[1].split("=")
            if l[0]!="#n":
                print("Error: "+lines[1])
                return None
            n=int(l[1])
            l=lines[2].split("=")
            if l[0]!="#e":
                print("Error: "+lines[2])
                return None
            e=int(l[1])
            l=lines[3].split("=")
            if l[0]!="#signature":
                print("Error: "+lines[3])
                return None
            signature=int(l[1])
            if lines[4]!="#End signature.\n":
                print("Error: "+lines[4])
                return None
            lines=lines[5:]
            msg=""
            for line in lines:
                msg+=line
            return clazz(msg,PublicKey(n,e), signature)

def genkeys ():
    print("Generating p.")
    p=4
    while isPrime(p)==False:
        p=ba2int(urandom(8))
    print("Generating q.")
    q=4
    while isPrime(q)==False:
        q=ba2int(urandom(9))
    print("Calculating n.")
    n=p*q
    print("Calculating the totient.")
    pmo=p-1
    qmo=q-1
    totient=math.lcm(pmo,qmo)
    print("Getting totient's divisors.")
    #dt = divisors(totient)
    print("Getting pmo divisors.")
    dt=divisors(pmo)
    print("Getting qmo divisors.")
    dt.extend(divisors(qmo))
    print("Generating e.")
    e=1
    while (e<2) or (e>=totient) or (haveCommon(divisors(e), dt)):
        e=urandom(1)[0]
        e=(e*256)+urandom(1)[0]
    print("Calculating d.")
    d=getD(e,totient)
    return KeysPair(n,e,d)

def main():
    uo=input("Enter 0 to generate keys, 1 to encrypt, 2 to decrypt, 3 to sign or 4 to verify a signature: ")
    if uo=="0":
        filename=input("Enter the name for the file: ")
        file=open(filename,"x")
        kp=genkeys()
        file.write(str(kp))
        file.close()
        exit()
    elif uo=="1":
        keyFileName=input("Enter the key file name: ")
        publicKey=KeysPair.read(keyFileName).getPublicKey()
        oFileName=input("Enter the ouput file name: ")
        of=open(oFileName,"x")
        message=input("Enter the message: ")
        of.write(str(EncryptedMessage(publicKey,message)))
        of.close()
        exit()
    elif uo=="2":
        keyFileName=input("Enter the key file name: ")
        privateKey=None
        if keyFileName:
            privateKey=KeysPair.read(keyFileName).getPrivateKey()
        print(EncryptedMessage.read(input("Enter the encrypted file name: ")).decrypt(privateKey))
        exit()
    elif uo=="3":
        keyFileName=input("Enter the key file name: ")
        kp=KeysPair.read(keyFileName)
        tfn=input("Enter the text file name: ")
        with open(tfn,"r") as tf:
            msg=tf.read()
        sm=SignedMessage(msg,kp)
        ofn=input("Enter the output file name: ")
        with open(ofn,"x") as of:
            of.write(str(sm))
    elif uo=="4":
        sfn=input("Enter the signed file name: ")
        sm=SignedMessage.read(sfn)
        if None==sm:
            print("Error parsing signature header.")
            exit()
        if sm.verify():
            print(f'n={sm.publicKey.n}\ne={sm.publicKey.e}\nThe signature is valid.')
            exit()
        else:
            print("The signature is not valid.")
            exit()
    else:
        print ("Unrecognized option.")
        exit()

if __name__=="__main__":
    main()
