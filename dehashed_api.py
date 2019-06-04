#!/usr/bin/env python3

from bs4 import BeautifulSoup
from time import sleep
from math import ceil
from json import loads
from os import path, makedirs
import requests
import csv

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"}

BASE_URI = "https://www.dehashed.com"
LOGIN_URI = BASE_URI + "/login"
SEARCH_URI = BASE_URI + "/search"
QUERY_URI = SEARCH_URI + "?query="
THROTTLE = 1
ERROR_THRESHOLD = 5
DUMP_NAME = 'full_dump.csv'
UN_NAME = 'usernames.txt'
PW_NAME = 'passwords.txt'
RULER_NAME = 'ruler_format.txt'
UNPW_NAME = 'username_password.csv'


class LoginError(Exception):
    pass


class EntryFailureError(Exception):
    pass


class DehashedAPI:

    session = None
    error_count = 0

    def __init__(self, username, password):
        self.authenticate(username, password)

    def authenticate(self, username, password):

        session = requests.session()
        session.get(LOGIN_URI)
        data = dict()
        data['password'] = password
        data['email'] = username
        response = session.post(LOGIN_URI, data=data, headers=HEADERS)
        if "Hello" in response.text:
            self.session = session
        else:
            raise LoginError

    def search(self, query, stdout=True, dump=False, unpw=False, un=False, pw=False, ruler=False, all=False):

        results = self.fetch_results(query)
        sorted_results = sorted(results, key=lambda k: k.get('username') or k.get('email'))

        if all:
            if not path.exists(all):
                makedirs(all)
            dump = path.join(all, DUMP_NAME)
            unpw = path.join(all, UNPW_NAME)
            un = path.join(all, UN_NAME)
            pw = path.join(all, PW_NAME)
            ruler = path.join(all, RULER_NAME)

        if stdout:
            self.print_results(sorted_results)
        if dump:
            self.dump_results(sorted_results, dump)
        if unpw:
            self.dump_un_pw_list(sorted_results, unpw)
        if un:
            self.dump_un_list(sorted_results, un)
        if pw:
            self.dump_pw_list(sorted_results, pw)
        if ruler:
            self.dump_ruler(sorted_results, ruler)

    def check_results(self, query):

        response = self.session.get(QUERY_URI + query, headers=HEADERS)
        parsed = BeautifulSoup(response.text, 'html.parser')
        query_meta = parsed.select("span.d-block strong")
        result_total = int(query_meta[0].string)
        return result_total

    def fetch_results(self, query):

        results = list()
        total = self.check_results(query)
        pages = ceil(total / 5)

        for page_num in range(pages):
            response = self.session.get(QUERY_URI + query + "&page={}".format(page_num + 1), headers=HEADERS)
            results = results + self.process_page(response.text)
            sleep(THROTTLE * 5)

        return results

    def process_page(self, content):

        page_results = list()
        parsed = BeautifulSoup(content, 'html.parser')
        entries = parsed.select("a.entry-link")
        for entry in entries:
            entry_id = entry.get('data-entry-id')
            try:
                entry_data = self.get_entry(entry_id)
                page_results.append(entry_data)
            except EntryFailureError:
                error_count = error_count + 1
                if error_count > self.ERROR_THRESHOLD:
                    raise Exception("Error Threshold Exceeded")
            sleep(THROTTLE)
        return page_results

    def get_entry(self, entry_id):

        response = self.session.get(SEARCH_URI + "/" + entry_id, headers=HEADERS)
        response_obj = loads(response.text)
        if response_obj.get('success', False):
            return response_obj['entry']
        else:
            raise EntryFailureError

    @classmethod
    def dump_un_pw_list(cls, results, unpw_file):

        ruler_pairs = list()

        for result in results:
            uname = result.get('username') or result.get('email')
            pword = result['password']

            if not uname or len(uname) < 1:
                continue
            if not pword or len(pword) < 1:
                continue

            ruler_pairs.append("{},{}".format(uname, pword))
            unique_pairs = list(set(ruler_pairs))

        with open(unpw_file, 'w') as file:
            for pair in unique_pairs:
                file.write("{}\n".format(pair))

    @classmethod
    def dump_pw_list(cls, results, pw_file):

        password_results = [res.get('password') for res in results]
        unique_results = list(set(password_results))

        with open(pw_file, 'w') as file:
            for result in unique_results:
                if result and len(result) > 0:
                    file.write("{}\n".format(result))

    @classmethod
    def dump_un_list(cls, results, un_file):

        username_results = [res.get('username') or res.get('email') for res in results]
        unique_results = list(set(username_results))

        with open(un_file, 'w') as file:
            for result in unique_results:
                if result and len(result) > 0:
                    file.write("{}\n".format(result))

    @classmethod
    def dump_ruler(cls, results, ruler_file):

        ruler_pairs = list()

        for result in results:
            uname = result['email'].split('@')[0]
            pword = result['password']

            if not uname or len(uname) < 1:
                continue
            if not pword or len(pword) < 1:
                continue

            ruler_pairs.append("{}:{}".format(uname, pword))
            unique_pairs = list(set(ruler_pairs))

        with open(ruler_file, 'w') as file:
            for pair in unique_pairs:
                file.write("{}\n".format(pair))

    @classmethod
    def dump_results(cls, results, dump_file):
        with open(dump_file, 'w') as csv_file:
            result_writer = csv.writer(csv_file)
            result_writer.writerow(["Id", "Email", "Username", "Password", "Hashed_password"
                                   , "Name", "VIN", "Address", "Ip_address", "Phone", "Obtained_from"])
            for result in results:
                result_writer.writerow([result['id'], result['email'], result['username'], result['password']
                                       , result['hashed_password'], result['name'], result['vin'], result['address']
                                       , result['ip_address'], result['phone'], result['obtained_from']])

    @classmethod
    def print_results(cls, results):
        print(results)


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser(description="DeHashed Results Parser")

    parser.add_argument('--username', dest='un', required=True, help='DeHashed Username')
    parser.add_argument('--password', dest='pw', required=True, help='DeHashed Password')
    parser.add_argument('--dump', dest='csv', default=False, help="Dump results to CSV file")
    parser.add_argument('--ruler', dest='ruler', default=False, help="Dump {un}:{pw} format")
    parser.add_argument('--pw', dest='pw', default=False, help="Dump list of passwords")
    parser.add_argument('--un', dest='un', default=False, help="Dump list of usernames")
    parser.add_argument('--unpw', dest='unpw', default=False, help="Dump lost of usernames/passwords")
    parser.add_argument('--all', dest='all', default=False, help="Dump all formats")
    parser.add_argument('--confirm', action='store_false', help="Bypass confirmation")
    parser.add_argument('query', help='Query String')

    args = parser.parse_args()
    un = args.un
    pw = args.pw
    query_term = args.query

    print("[*] Authenticating...")
    try:
        api = DehashedAPI(un, pw)
        print("[+] Success!")
        print("[*] Checking Query: {}...".format(query_term))
        num = api.check_results(query_term)
        approx_time_sec = (num * THROTTLE) + ((num/5) * (THROTTLE * 5))
        approx_time_min = round((approx_time_sec/60),2)
        print("[+] Results: {}".format(num))
        if args.confirm:
            input("[!] Press Enter to start fetching (Approximately {} minutes to complete)...".format(approx_time_min))
        print("[*] Querying: {}...".format(query_term))
        api.search(query_term, dump=args.csv, ruler=args.ruler, all=args.all, unpw=args.unpw, un=args.un, pw=args.pw)
    except LoginError as e:
        print("[-] Failed to authenticate")
