#!/usr/bin/env python3

from bs4 import BeautifulSoup
from time import sleep
from math import ceil
from json import loads
import requests
import csv

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"}

BASE_URI = "https://www.dehashed.com"
LOGIN_URI = BASE_URI + "/login"
SEARCH_URI = BASE_URI + "/search"
QUERY_URI = SEARCH_URI + "?query="
THROTTLE = 1


class LoginError(Exception):
    pass


class EntryFailureError(Exception):
    pass


class DehashedAPI:

    ERROR_THRESHOLD = 5
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

    def search(self, query, stdout=True, dump=False, unpw=False, un=False, pw=False):

        results = self.fetch_results(query)
        sorted_results = sorted(results, key=lambda k: k.get('username') or k.get('email'))

        if stdout:
            self.print_results(sorted_results)
        if dump:
            self.dump_results(sorted_results, dump)
        if unpw:
            self.dump_un_pw_list(sorted_results)
        if un:
            self.dump_un_list(sorted_results)
        if pw:
            self.dump_pw_list(sorted_results)

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
    def dump_un_pw_list(cls, results):
        pass

    @classmethod
    def dump_pw_list(cls, results):
        pass

    @classmethod
    def dump_un_list(cls, results):
        pass

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
        input("[!] Press Enter to start fetching (Approximately {} minutes to complete)...".format(approx_time_min))
        print("[*] Querying: {}...".format(query_term))
        api.search(query_term, dump=args.csv)
    except LoginError as e:
        print("[-] Failed to authenticate")
