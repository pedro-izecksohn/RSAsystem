from os import urandom
import math

def divisors (number):
    ret=[]
    if number<2:
        return ret
    curdiv = 2
    while (number%2)==0:
        ret.append(2)
        number=number//2
    curdiv=3
    sqn=number**0.5
    while curdiv <= sqn:
        if (number%curdiv)==0:
            ret.append(curdiv)
            number = number//curdiv
        else:
            curdiv += 2
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

def getD (e:int,totient:int):
    d=1
    mulres=e
    while (mulres%totient)!=1:
        d+=1
        mulres+=e
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
        
def genkeys ():
    p=4
    while isPrime(p)==False:
        p=urandom(1)[0]
        p=(p*256)+urandom(1)[0]
    q=4
    while isPrime(q)==False:
        q=urandom(1)[0]
        q=(q*256)+urandom(1)[0]
    n=p*q
    totient=math.lcm(p-1, q-1)
    dt = divisors(totient)
    e=1
    while (e<2) or (e>=totient) or (haveCommon(divisors(e), dt)):
        e=urandom(1)[0]
        e=(e*256)+urandom(1)[0]
    d=getD(e,totient)
    return KeysPair(n,e,d)

def main():
    uo=input("Enter 0 to generate keys, 1 to encrypt or 2 to decrypt: ")
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
    else:
        print ("Unrecognized option.")
        exit()

if __name__=="__main__":
    main()
