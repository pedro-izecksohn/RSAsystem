from os import urandom

def divisors (number):
    ret=[]
    if number<2:
        return ret
    curdiv = 2
    while curdiv < number:
        if (number%curdiv)==0:
            ret.append(curdiv)
            number = number//curdiv
        else:
            curdiv += 1
    ret.append(number)
    return ret

def isPrime(i):
    if (i<2):
        return False
    div=1
    while div<i:
        div+=1
        if (i%div)==0:
            return False
    return True

def haveCommon (l1, l2):
    for i in l1:
        if i in l2:
            return True
    return False

def lcm (a, b):
    if (a==0) or (b==0):
        return 1
    if a==b:
        return a
    elif a>b:
        a,b=b,a
    if (b%a)==0:
        return b
    divisor=1
    ret=1
    while (a!=1)or(b!=1):
        divisor+=1
        while ((a%divisor)==0) and ((b%divisor)==0):
            a//=divisor
            b//=divisor
            ret*=divisor
        while ((a%divisor)==0):
            a//=divisor
            ret*=divisor
        while ((b%divisor)==0):
            b//=divisor
            ret*=divisor
    return ret

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
                m=(c**self.d)%self.n
                dic[c]=m
                lout.append(m)
        ba=bytearray(lout)
        ret=ba.decode("utf-8")
        return ret

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
        totient=lcm (p-1, q-1)
        print ("totient="+str(totient))
        if (self.e<=1) or (self.e>=totient):
            raise Exception ("Invalid e.")
        d=1
        while ((e*d)%totient)!=1:
            d+=1
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
                c=((m**self.e)%self.n)
                d[m]=c
                ret.append(c)
        return ret

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
    totient=lcm(p-1, q-1)
    dt = divisors(totient)
    e=1
    while (e<2) or (e>=totient) or (haveCommon(divisors(e), dt)):
        e=urandom(1)[0]
        e=(e*256)+urandom(1)[0]
    d=1
    while ((e*d)%totient)!=1:
        d+=1
    return PublicKey(n,e), PrivateKey(n,d)

pk=None
privk=None
hk = input ("Do you have the key? Answer y or n: ")
if (hk=="n"):
    pk, privk = genkeys()
    print ("n="+str(pk.n))
    print ("e="+str(pk.e))
    print ("d="+str(privk.d))
n=int(input("Enter the number n: "))
choice=input("Enter the character e to encrypt or the character d to decrypt: ")
if choice=='e':
    e=int(input("Enter the number e: "))
    pk=PublicKey(n,e)
    m=input("Enter the message: ")
    l=pk.encrypt(m)
    print(l)
elif choice=='d':
    have=input("Do you have the number d? Answer y or n: ")
    privk=None
    if have=='y':
        d=int(input("Enter the number d: "))
        privk=PrivateKey(n,d)
    elif have=='n':
        e=int(input("Enter the number e: "))
        pk=PublicKey(n,e)
        privk=pk.getPrivateKey()
    else:
        print("Unrecognized option.")
        exit()
    l=[]
    while True:
        i=input("Enter a number of the message: ")
        if i=="":
            break
        else:
            l.append(int(i))
    s=privk.decrypt(l)
    print(s)
else:
    print ("Unrecognized choice.")
