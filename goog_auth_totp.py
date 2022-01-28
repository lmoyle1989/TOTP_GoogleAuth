#
# Program Name - Google Authenticator HOTP/TOTP Implementation
# Author - Lucas Moyle
# Description - This program implements the HOTP/TOTP algorithms outlined in rfc4226/rfc6238, respectively, for use with the Google Authenticator Android App
#               The program generates a qr code that contains the URI information that can be scanned with the google auth app.
#               Once created and succesfully scanned, the program then can generate corresponding time based one times passwords.
#               
# Notes -   All reference material used from rfc4226 & rfc6238
#           https://datatracker.ietf.org/doc/html/rfc4226
#           https://datatracker.ietf.org/doc/html/rfc6238

import qrcode
import sys
import time
import base64
import hashlib
import hmac

class GoogleAuthOTP:

    def __init__(self):
        # UTF-8 plaintext key, will be encoded to base32 for the URI
        self.key_string = 'here_is_my_test_key'
        self.key32 = base64.b32encode(bytes(self.key_string, encoding='UTF-8')) 
        self.key32_string = self.key32.decode('UTF-8')
        # Change this if you want a different user name, note don't include spaces or the URI will not be generated properly
        self.user_string = 'moylel@oregonstate.edu'
        # Change this if you want a different issuer name, don't use spaces again
        self.issuer_string = 'CS370'
        # Generate our URI for the qr code
        self.auth_uri_string = 'otpauth://totp/' + self.issuer_string + ':' + self.user_string + '?secret=' + self.key32_string + '&issuer=' + self.issuer_string + '&algorithm=SHA1&digits=6&period=30'

    # generate_qr_code()
    # uses the qrcode library to generate a qr code containing uri info that can be used with google authenticator, according to guidelines here:
    # https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    # qr code will be saved as file_name.png in the current working directory
    # @file_name - name of qr code image file, will append '.png' to the end
    def generate_qr_code(self, file_name):
        my_qr = qrcode.make(self.auth_uri_string)
        my_qr.save(file_name + '.png')

    # get_hotp()
    # HOTP algorithm that returns a 6 digit base 10 number which should match a corresponding HOTP authenticator
    # @key - base32 encoded secret key
    # @counter - an integer representing the current count of authentication uses
    def get_hotp(self, key, counter):
        # decode our base32 encoded key into a bytes object
        key_bytes = base64.b32decode(key)
        # turn out counter integer into an 0-padded 8-byte bytes object of equal value 
        counter_8bytes = counter.to_bytes(8, 'big')
        # hash our key and counter w/ sha1 
        hmac_hash = hmac.new(key_bytes, counter_8bytes, hashlib.sha1).digest()
        # find our byte offset by taking the value of the last 4 bits of the hash
        truncate_index = (hmac_hash[19] % 16)
        # take a 4 byte slice of the hash bytes according to our offset
        truncated_hash_32 = hmac_hash[truncate_index:truncate_index+4]
        # turn our sliced bytes and convert them into a 4-byte integer
        int_32 = int.from_bytes(truncated_hash_32, 'big')
        # ensure the first bit of the 4-byte integer is 0 according to rfc, using a bitwise AND with 7FFFFFFF
        int_31 = int_32 & 0x7FFFFFFF
        # return our 6 digit mod'ed result according to rfc
        result = int_31 % 10**6
        return result

    # get_totp()
    # returns the 6 digit TOTP authentication code that corresponds to the google authenticator
    # @key - base32 encoded secret key
    def get_totp(self, key):
        # get unix time and divide by 30
        totp_time = int(time.time() // 30)
        # call our hotp function with the time instead of a counter
        result = self.get_hotp(key, totp_time)
        return result


if __name__ == '__main__':
    if len(sys.argv) != 2:
        pass
    else:
        my_auth = GoogleAuthOTP()
        if sys.argv[1] == '--generate-qr':
            my_auth.generate_qr_code('my_qr')
        elif sys.argv[1] == '--get-otp':
            print(my_auth.get_totp(my_auth.key32))
        else:
            print("Incorrect parameter. Use '--generate-qr' or '--get-otp'")