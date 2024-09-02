# pip install requests
# SHA1 Website: https://passwordsgenerator.net/sha1-hash-generator/

import sys

import requests
import hashlib


# Actual password passwords1234 then use SHA1 Hash generator to hash the passwors
# hashed pwd: B28F743EB6A1934053B8C3BCD46A50FF6B52B43F


def request_api_data(query_char):
    """ Function that checks for first 5 characher of our hashed pwd to see matches for data leak"""
    URL = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(URL, timeout=10)
    # Raise error if server's response status code is anything other than 200
    if res.status_code != 200:
        raise RuntimeError(
            f"error Fetching: {res.status_code}, check API again")
    return res


def pawned_api_checker(password):
    """Converting the users password into a sha1 encoded password """
    # hexdigest converts the hashed password object into a hexa decimal string and upper is ALL CAPS
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # Split the hashed password into two parts. The first 5 characters are tested against a
    # database of hacked passwords. We receive a list of SHA-1 hashes that match our first
    # five characters. Then, we check our full SHA-1 hash against this list. This method
    # ensures the highest level of security because it prevents your actual password from
    # being exposed during the internet session when you type it into a website.
    first_five_char, tail = sha1password[:5], sha1password[5:]
    # print(first_five_char,  tail)
    # calling the function that interacts with the api which returns
    #  a list of passwords and number of times it has been hacked
    response = request_api_data(first_five_char)
    # print(response)
    return get_password_leak_count(response, tail)



def get_password_leak_count(hash_list, original_hash_pwd):
    """This fucnction checks if our password exists in the list we got from the api"""
    # split each hash by : by doing a tuple comprehension
    hashes = (line.split(':')for line in hash_list.text.splitlines())
    for h, count in hashes:
        if h == original_hash_pwd:
            return count
    return 0
        # print(h, count)



def main(args):
    """The main function that checks the passwords for us"""
    for passwords in args:
        count = pawned_api_checker(passwords)
        # chercking if count exists
        if count :
            print(f'{passwords} was found {count} times. You should change your password NOW!!')
        else:
            print(f"{passwords} was not found :)")
        
    return "Done!"


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
# pawned_api_checker("passwords1234")
