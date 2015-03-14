import httplib
import time
conn = httplib.HTTPConnection("localhost:8080")


#time.sleep(70)
conn.request("GET", "http://www.sohu.com/")
r1 = conn.getresponse()
print(r1.status, r1.reason)

r1.read()
time.sleep(70)

conn.request("GET", "http://www.sohu.com/")
r1 = conn.getresponse()
print(r1.status, r1.reason)

r1.read()
conn.close()
