# Casare Algorithm
print "-----------------"
def convert(c, key, start = 'a', n = 26):
    a = ord(start)
    offset = ((ord(c) - a + key)%n)
    return chr(a + offset)
def caesarEncode(s, key):
    o = ""
    for c in s:
        if c.islower():
            o+= convert(c, key, 'a')
        elif c.isupper():
            o+= convert(c, key, 'A')
        else:
            o+= c
    return o
def caesarDecode(s, key):
    return caesarEncode(s, -key)
if __name__ == '__main__':
    #This is the rot key
    print "please input number"
    key = input()
    #This is the password
    print "please input caeser password"
    s = raw_input()
    #after encode caesar password 
    print "----------------------"
    e = caesarEncode(s, key)
    #This is the password
    print "the carserEncode is :"
    d = caesarDecode(e, key)
    print e
    print "the carserDecode is :"
    print d
print "----------------------"
