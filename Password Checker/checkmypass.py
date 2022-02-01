import requests
import hashlib
import sys


def requests_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_passwd_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':')for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(passwd):
    sha1passwd = hashlib.sha1(passwd.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1passwd[:5], sha1passwd[5:]
    response = requests_api_data(first5_char)
    return get_passwd_leaks_count(response, tail)


def main(args):
    for passwd in args:
        count = pwned_api_check(passwd)
        if count:
            print(
                f'{passwd} was found {count} times... you should probably change your psswrd!')
        else:
            print(f'{passwd} was NOT found. Carry on!')
    return 'done!'


# Note: We can also give our password to the terminal by using the FileIO to increase our security.
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
