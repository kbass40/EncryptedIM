# EnncryptedIM

Simple Unencrypted IM service built using python3.
Updated to add encryption.

# How to run:

1st run server with: "python3 UnencryptedIM.py -s {portnumber}"

2nd run client with: "python3 UnencryptedIM.py -c {hostname} {portnumber}"
  
  
  portnumber can be ommitted and will default to port 9999
  
  Example:
  
  First run: python3 UnencryptedIM.py -s 12345
  
  Then run: python3 UnencryptedIM.py -c lin114-09 12345
  
  The lin114-09 will be the host machine you are attempting to connect to.
