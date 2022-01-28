# Program Name - Google Authenticator HOTP/TOTP Implementation
# Author - Lucas Moyle
# Date - 11/14/2021

RUNNING THE PROGRAM:
1. run the program with the command line argument '--generate-qr'
	$ python3 goog_auth_totp.py --generate-qr
2. a .png file will be created in the current working directory with the program .py file
3. scan the qrcode with the Google Authenticator app
4. run the program again with the command line argument '--get-otp'
	$ python3 goog_auth_totp.py --get-otp
5. the program will output a matching 30-second TOTP 6-digit number which will match what is shown in the authenticator app

ADDITIONAL NOTES:
I suggest you do not but-
If you want to use a different user account name, secret key, or issuer, change the following variables in the GoogleAuthOTP object __init__ function
self.key_string
self.user_string
self.issuer_string
A new qr code will need to be generated if any of these change.
Note do not use spaces or special characters in these variables, the program is not robust enough to convert them into a readable URI (e.g. space chars becoming %20 in the URI doesnt happen)

See code comments for details on my HOTP/TOTP implementations.




