#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Download more than 100 files product of a VT Intelligence search.

VirusTotal Intelligence allows you to download up to the top100 files that
match a given search term. The 100 file limit is a server-side limitation
when creating the file packages. In order to overcome this limitation this
small script has been developed, it will paginate over a given Intelligence
search and download the matching files individually.
"""

__author__ = 'emartinez@virustotal.com (Emiliano Martinez)'

import queue
from urllib.parse import urlencode

from pip._vendor import requests, urllib3

"""
Addition to search only for files from today using TODAY_IS variable. T Kendrick
In addition, added the MAGIC varliable, so that we can pre-configure the search
*looking for doc and pdf (or just one type) 
*with a tag (to make it more likely malicious and filter out some junk) 
*for at least 2 positives, but under 10
*not found by KAV, BitDefender or Microsoft  
Just comment out which ever version of "MAGIC" you want to include. The lower in the list, the more results.

"""

import json
import logging
import optparse
import os
import re
import socket
import sys
import threading
import time

TODAY_IS = time.strftime('%Y-%m-%dT00:00:00+')
MAGIC = "(microsoft:clean symantec:clean kaspersky:clean bitdefender:clean positives:2+ positives:10-) AND ((type:doc AND tag:environ) OR (type:pdf AND tag:autoaction))"  ##This is a standard search but returns least results, +2 -10, and Docs looking for environemtn info, and PDF, trying to launch stuff. -- TKendrick
# MAGIC = "(microsoft:clean symantec:clean kaspersky:clean bitdefender:clean positives:2+ positives:10-) AND ((type:doc AND tag:environ) OR (type:pdf))" ##This search is, +2 -10, and Docs looking for environemtn info, and PDF, but no tags. -- TKendrick
# MAGIC = "(microsoft:clean symantec:clean kaspersky:clean bitdefender:clean positives:4+ positives:10-) AND ((type:doc) OR (type:pdf) OR (type:peexe))" ##This search is, +2 -10, and Docs or PDF, but you dont know what file does what! Be careful. -- TKendrick
# MAGIC = "(microsoft:clean symantec:clean kaspersky:clean bitdefender:clean positives:2+ positives:10-) AND (type:doc AND tag:environ)" ##This is a standard search, +2 -10, and Docs looking for environemtn info. -- TKendrick
# MAGIC = "(microsoft:clean symantec:clean kaspersky:clean bitdefender:clean  positives:2+ positives:10-) AND (type:pdf AND tag:autoaction)" ##This is a standard search, +2 -10, and PDF, trying to launch stuff -- TKendrick


INTELLIGENCE_SEARCH_URL = ('https://www.virustotal.com/intelligence/search/'
                           'programmatic/')
INTELLIGENCE_DOWNLOAD_URL = ('https://www.virustotal.com/intelligence/download/'
                             '?hash=%s&apikey=%s')

NUM_CONCURRENT_DOWNLOADS = 10

LOCAL_STORE = 'SAMPLEFILES'

socket.setdefaulttimeout(60)

LOGGING_LEVEL = logging.DEBUG  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)


class Error(Exception):
    """Base-class for exceptions in this module."""


class InvalidQueryError(Error):
    """Search query is not valid."""


def create_download_folder(query=None):
    """Creates a folder to store the downloaded files.

    The Intelligence query issues is stored in a separate txt file inside the
    directory created, this will allow the user to remember the query he performed
    at a later time.

    Args:
      query: the Intelligence search query, as a string, that is issued in order
        to save the corresponding files to the directory being created.

    Returns:
      String with the path of the created folder.
    """
    folder_name = time.strftime('%Y%m%dT%H%M%S')
    if not os.path.exists(LOCAL_STORE):
        os.mkdir(LOCAL_STORE)
    folder_path = os.path.join(LOCAL_STORE, folder_name)
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
    if query:
        query_path = os.path.join(folder_path, 'intelligence-query.txt')
        with open(query_path, 'w+') as query_file:
            query_file.write(query)
    return folder_path


def get_matching_files(search, page=None):
    """Get a page of files matching a given Intelligence search.

    Args:
      search: a VirusTotal Intelligence search phrase. More about Intelligence
        searches at: https://www.virustotal.com/intelligence/help/
      page: a token indicating the page of file results that should be retrieved.

    Returns:
      Tuple with a token to retrieve the next page of results and a list of sha256
      hashes of files matching the given search conditions.

    Raises:
      InvalidQueryError: if the Intelligence query performed was not valid.
    """
    response = None
    page = page or 'undefined'
    attempts = 0
    parameters = {'query': search, 'apikey': VT_API_KEY, 'page': page}
    data = urlencode(parameters)
    while attempts < 10:
        try:
            r = requests.post(INTELLIGENCE_SEARCH_URL, data=data)
            response = r.content
            break
        except Exception:
            attempts += 1
            time.sleep(1)
    if not response:
        return (None, None)

    try:
        response_dict = json.loads(response)
    except ValueError:
        return (None, None)

    if not response_dict.get('result'):
        raise InvalidQueryError(response_dict.get('error'))

    next_page = response_dict.get('next_page')
    hashes = response_dict.get('hashes', [])
    return (next_page, hashes)


def download_file(file_hash, VT_API_KEY, destination_file=None):
    """Downloads the file with the given hash from Intelligence.

    Args:
      file_hash: either the md5, sha1 or sha256 hash of a file in VirusTotal.
      destination_file: full path where the given file should be stored.
      VT_API_KEY: API key for virus total, you can get in profile settings.

    Returns:
      True if the download was successful, False if not.
    """
    destination_file = destination_file or file_hash
    download_url = INTELLIGENCE_DOWNLOAD_URL % (file_hash, VT_API_KEY)
    attempts = 0
    while attempts < 3:
        try:
            with requests.get(download_url, stream=True) as r:
                r.raise_for_status()
                with open(destination_file, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            return True
        except Exception:
            attempts += 1
    return False


def download_files_from_VT(numfiles, VT_API_KEY, MAGIC):
    """Download the top-n results of a given Intelligence search."""
    usage = 'usage: %prog -n # (specify a number of values to search for)'
    parser = optparse.OptionParser(
        usage=usage, description='Allows you to download the top-n files returned by a given')
    parser.add_option('-n', '--numfiles', dest='numfiles', default=100, help='number of files to download')
    (options, args) = parser.parse_args()
    if not args:
        (options, args) = parser.parse_args()

    end_process = False
    search = ' '.join(args)
    search = search.strip().strip('\'')
    search = search + " " + MAGIC + " fs:" + TODAY_IS  ##Here is the action by TK to add the magic, and add the search only from today.  If you dont like the today, you can hard code, in format of fs:YYYY-MM-DDT00:00:00+ - see below for example, and switch line
    ##Example for above is search = search+" "+MAGIC+" fs:2019-12-25T00:00:00+"

    if os.path.exists(search):
        with open(search, 'rb') as file_with_hashes:
            content = file_with_hashes.read()
            requested_hashes = re.findall(
                '([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})', content)
            search = ','.join(set(requested_hashes))

    logging.info('Starting VirusTotal Intelligence downloader')
    logging.info('* VirusTotal Intelligence search: %s', search)
    logging.info('* Number of files to download: %s', numfiles)

    work = queue.Queue()  # Queues files to download
    end_process = False

    def worker(VT_API_KEY):
        while not end_process:
            try:
                sha256, folder = work.get(True, 3)
            except queue.Empty:
                continue
            destination_file = os.path.join(folder, sha256)
            logging.info('Downloading file %s', sha256)
            success = download_file(sha256, VT_API_KEY, destination_file=destination_file)
            if success:
                logging.info('%s download was successful', sha256)
            else:
                logging.info('%s download failed', sha256)
            work.task_done()

    threads = []
    for unused_index in range(NUM_CONCURRENT_DOWNLOADS):
        thread = threading.Thread(target=worker, args=[VT_API_KEY])
        thread.daemon = True
        thread.start()
        threads.append(thread)

    logging.info('Creating folder to store the requested files')
    folder = create_download_folder(search)

    queued = 0
    wait = False
    next_page = None
    while not end_process:
        try:
            logging.info('Retrieving page of file hashes to download')
            try:
                next_page, hashes = get_matching_files(search, page=next_page)
            except InvalidQueryError as e:
                logging.info('The search query provided is invalid... %s', e)
                raise InvalidQueryError
            if hashes:
                logging.info(
                    'Retrieved %s matching files in current page, queueing them',
                    len(hashes))
                for file_hash in hashes:
                    work.put([file_hash, folder])
                    queued += 1
                    if queued >= numfiles:
                        logging.info('Queued requested number of files')
                        wait = True
                        break
            if not next_page or not hashes:
                logging.info('No more matching files')
                wait = True
            if wait:
                logging.info('Waiting for queued downloads to finish')
                while work.qsize() > 0:
                    time.sleep(5)
                end_process = True
                for thread in threads:
                    if thread.is_alive():
                        thread.join()
                logging.info('The downloaded files have been saved in %s', folder)
                return folder
        except KeyboardInterrupt:
            end_process = True
            logging.info('Stopping the downloader, initiated downloads must finish')
            for thread in threads:
                if thread.is_alive():
                    thread.join()


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECONDS_TO_WAIT = 5


def move_file_per_verdict(self, verdict):
    if verdict['severity'] is None:
        return
    if verdict['severity'] >= 4:  # critical
        os.rename(self.file_path, self.output_folder + '\high\\' + self.file_name)
    if verdict['severity'] == 3:
        os.rename(self.file_path, self.output_folder + '\medium\\' + self.file_name)


def parse_file_verdict(response):
    """
    parse and print the te verdict of current handled file
    """
    try:
        verdict = {'verdict': response["response"][0]["te"]["combined_verdict"],
                   'severity': response["response"][0]["te"].get('severity', None)
                   }
        logging.info("te verdict is: {} for file {}".format(verdict, response['response']))

    except:
        verdict = {'verdict': response["response"]["te"]["combined_verdict"],
                   'severity': response["response"]["te"].get('severity', None)}
        logging.info("te verdict is: {} for file {}".format(verdict, response['response']))

    return verdict


def resolve_images_from_name(images):
    result = []
    for img in images:
        if img.lower() == 'winxp':
            result.append({
                'id': 'e50e99f3-5963-4573-af9ee3f4750b55e2',
                'revision': 1
            })
        elif img.lower() == 'win8':
            result.append({
                'id': '6c453c9b-20f7-471a-956c3198a868dc92',
                'revision': 1
            })
        elif img.lower() == 'win10':
            result.append({
                'id': '10b4a9c6-e414-425c-ae8bfe4dd7b25244',
                'revision': 1
            })

    return result


class TE(object):
    """
    this class gets a file as input. The methods will upload the file to TE, query until an answer is
    received, and parse the response.
    Notice that if TE should run separately, a separate parsing response method should be added.
    """

    def __init__(self, url, file_name, file_path, output_folder, TE_API_KEY, images):
        self.images = None
        self.attempts = 0
        self.url = url
        self.file_name = file_name
        self.file_path = file_path
        self.upload_request = {"request": [{"features": ["te"]}]}
        self.query_request = {
            "request": [{"sha1": "", "features": ["te"], "te": {"images": []}, "reports": ['summary']}]}
        self.output_folder = output_folder
        self.sha1 = ""
        self.TE_API_KEY = TE_API_KEY
        self.headers = {'Authorization': '{}'.format(self.TE_API_KEY)} if TE_API_KEY is not None else ''

    def create_response_data_file(self, response):
        """
        upload the file to the appliance
        """

        output_path = os.path.join(self.output_folder, self.file_name)
        output_path += ".response.txt"
        with open(output_path, 'w+') as file:
            json.dump(response, file)

    def query_file(self):
        """
        query the appliance for the file every SECONDS_TO_WAIT seconds
        """
        request = self.query_request
        request['request'][0]['sha1'] = self.sha1
        request['request'][0]['te']['images'] = self.images
        data = json.dumps(request)
        response_j = json.loads('{}')
        label = False
        while label != "FOUND":
            logging.debug("Sending TE Query request")
            response = requests.post(url=self.url + "query", data=data, verify=False, headers=self.headers)
            response_j = response.json()
            label = response_j["response"][0]["te"]["status"]["label"]
            if label == "FOUND":
                break
            time.sleep(SECONDS_TO_WAIT)
        return response_j

    def upload_file(self):
        """
        upload the file to the appliance
        """
        request = self.upload_request
        data = json.dumps(request)
        file = open(self.file_path, 'rb')
        curr_file = {
            'request': data,
            'file': file
        }
        logging.debug("Sending TE Upload request")
        response = requests.post(url=self.url + "upload", files=curr_file, verify=False, headers=self.headers)
        response_j = response.json()
        return response_j

    def handle_file(self):
        """
        1. Upload the file to the appliance
        2. If result is upload_success then query the file every SECONDS_TO_WAIT until receiving found result
           Otherwise, if result is already found then continue
           Otherwise, exit
        3. Save the upload/query response of found result in a file in the relevant folder
        """
        upload_response = self.upload_file()
        logging.debug("Receiving TE Upload response")
        logging.info("Upload result: {}".format(upload_response["response"][0]["te"]["status"]["label"]))
        upload_return_code = upload_response["response"][0]["te"]["status"]["code"]
        if upload_return_code == 1002:
            logging.debug("upload response: {}".format(upload_response))
            self.sha1 = upload_response["response"][0]["sha1"]
            logging.debug("sha1: {}".format(self.sha1))
            logging.info("Receiving TE Query-with-Found response")
            query_response = self.query_file()
        elif upload_return_code == 1001:
            query_response = upload_response
        else:
            logging.error(
                "Upload resulted with failure: {}".format(upload_response["response"][0]["te"]["status"]["label"]))
            return False
        verdict = parse_file_verdict(query_response)
        self.create_response_data_file(query_response)
        move_file_per_verdict(self, verdict)
        return True

    def handle_file_cloud(self):
        """
        1. Upload the file to the appliance
        2. If result is upload_success then query the file every SECONDS_TO_WAIT until receiving found result
           Otherwise, if result is already found then continue
           Otherwise, exit
        3. Save the upload/query response of found result in a file in the relevant folder
        """
        upload_response = self.upload_file_cloud()
        if not upload_response:
            return True
        logging.debug("Receiving TE Upload response")
        logging.info("Upload result: {}".format(upload_response["response"]["te"]["status"]["label"]))
        upload_return_code = upload_response["response"]["te"]["status"]["code"]
        if upload_return_code == 1002:
            logging.debug("upload response: {}".format(upload_response))
            self.sha1 = upload_response["response"]["sha1"]
            logging.debug("sha1: {}".format(self.sha1))
            logging.info("Receiving TE Query-with-Found response")
            query_response = self.query_file()
        elif upload_return_code == 1001:
            query_response = upload_response
        elif upload_return_code == 1003:
            if self.attempts > 10:
                logging.error("Failed to upload file {}".format(self.file_name))
                self.attempts = 0
                return True
            logging.info("Pending request")
            self.attempts += 1
            return False
        else:
            logging.error(
                "Upload resulted with failure: {}".format(upload_response["response"]["te"]["status"]["label"]))
            return True
        verdict = parse_file_verdict(query_response)
        self.create_response_data_file(query_response)
        move_file_per_verdict(self, verdict)
        return True

    def upload_file_cloud(self):
        '''Will Win 10 as images and upload to cloud'''
        if self.images is None:
            self.images = [{
                "id": "10b4a9c6-e414-425c-ae8b-fe4dd7b25244",
                "revision": 1
            }]
        request = {
            "request": {
                "file_name": self.file_name,
                "file_type": "",
                "features": ["te"],
                "te": {
                    "images": self.images,
                    "reports": ["summary"]
                }
            }
        }
        data = json.dumps(request)
        try:
            file = open(self.file_path, 'rb')
        except:
            logging.error("File not found {}".format(self.file_name))
            return False
        if get_file_size(file) / 1024 / 1024 > 25:
            logging.error("File too large {}".format(self.file_name))
            return False

        curr_file = {
            'request': data,
            'file': file
        }

        logging.debug("Sending TE Upload request")
        try:
            response = requests.post(url=self.url + "upload", files=curr_file, verify=False, headers=self.headers)
            response_j = response.json()
        except Exception as e:
            logging.error("Failed to process file {}".format(self.file_name))
            return False
        return response_j


def create_out_folder(output_folder):
    # check if folder exists
    if not os.path.exists(output_folder):
        os.mkdir(output_folder)
    if not os.path.exists(output_folder + '\high'):
        os.mkdir(output_folder + '\high')
    if not os.path.exists(output_folder + '\medium'):
        os.mkdir(output_folder + '\medium')


def te_worker(te_work):
    while True:
        try:
            url, file, file_path, te_work, te_response_folder, TE_API_KEY, images = te_work.get(True, 3)
        except queue.Empty:
            break

        logging.info('Processing file %s', file)

        te = TE(url, file, file_path, te_response_folder, TE_API_KEY, images)

        if TE_API_KEY is None:
            te.handle_file()
        else:
            cloud_result = False
            while not cloud_result:
                cloud_result = te.handle_file_cloud()
                time.sleep(2)

        logging.info('File analyzed %s', file)
    te_work.task_done()


def send_to_sandbox(folder, te_ip='te.checkpoint.com', TE_API_KEY=None, images=None):
    files_to_check = os.listdir(folder)
    te_response_folder = "TE_FOLDER_" + folder.split(LOCAL_STORE + '\\')[1]

    url = "https://{}/tecloud/api/v1/file/".format(te_ip)
    te_work = queue.Queue()  # Queues files to SB
    create_out_folder(te_response_folder)
    threads = []
    for unused_index in range(NUM_CONCURRENT_DOWNLOADS):
        thread = threading.Thread(target=te_worker, args=[te_work])
        thread.daemon = True
        thread.start()
        threads.append(thread)

    queued = 0
    end_process = False
    wait = False
    while not end_process:
        try:
            if files_to_check:
                logging.info("We need to check {} files".format(len(files_to_check)))
                for file in files_to_check:
                    file_path = os.path.join(folder, file)
                    te_work.put([url, file, file_path, te_work, te_response_folder, TE_API_KEY, images])
                    queued += 1
                    if queued >= len(files_to_check):
                        logging.info('Queued requested number of files')
                        wait = True
                        break
            if wait:
                logging.info('Waiting for queued files analyzing')
                while te_work.qsize() > 0:
                    time.sleep(5)
                end_process = True
                for thread in threads:
                    if thread.is_alive():
                        thread.join()
                logging.info('The analyzed files have been processed from folder: %s ', folder)
                return folder

        except KeyboardInterrupt:
            end_process = True
            logging.info('Stopping the TE daemons')
            for thread in threads:
                if thread.is_alive():
                    thread.join()


def get_file_size(upstream):
    upstream.seek(0, 2)  # end of file
    file_size = upstream.tell()
    upstream.seek(0)
    return file_size


if __name__ == '__main__':
    numfiles = int(input("Number of files to search for[100]: ") or "100")  # default 100 files
    VT_API_KEY = str(input("Enter VT API KEY: ") or '')
    MAGIC = str(input(
        'Enter magic search string or use default: ') or "(microsoft:clean symantec:clean kaspersky:clean bitdefender:clean positives:4+ positives:10-) AND ((type:doc) OR (type:pdf) OR (type:peexe))")
    TE_API_KEY = str(
        input("Enter SandBlast TE Cloud API Key:  ") or "")

    if len(VT_API_KEY) == 0 or len(TE_API_KEY) == 0:
        logging.error("API KEY invalid")
        raise InvalidQueryError
    folder = download_files_from_VT(numfiles, VT_API_KEY, MAGIC)
    TE_result = send_to_sandbox(folder, TE_API_KEY=TE_API_KEY, images=None)
    # TE_result = send_to_sandbox(folder, te_ip='10.142.0.30:18194')
