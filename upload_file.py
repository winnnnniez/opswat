import sys
import hashlib
import requests
import time

# Please enter your apikey here
api_key = ""

class File:
    """
    File object:
        File.name <Str>: file name
        File.content <Bytes>: content of the file in binary format
        File.md5 <Str>: md5 hash
        File.sha1 <Str>: sha1 hash
        File.sha256 <Str>: sha256 hash

    # only sha256 is used for hash lookup in this program
    """
    def __init__(self, file_name):
        self.name = file_name
        with open(file_name, "rb") as f:
            self.content = f.read()
        self.md5 = hashlib.md5(self.content).hexdigest()
        self.sha1 = hashlib.sha1(self.content).hexdigest()
        self.sha256 = hashlib.sha256(self.content).hexdigest()

def upload_file(file, api_key):
    """
    takes a file and api key, upload the file
    returns the data id of the uploaded file
    returns empty string if error occurred

    File, Str -> Str
    """

    # url & headers for calling api
    url_upload = "https://api.metadefender.com/v4/file/"
    header_upload = {
        "apikey": api_key,
        "Content-Type": "application/octet-stream",
        "filename": file.name
    }

    # get response
    res_upload = requests.post(url_upload, headers=header_upload, data=file.content)

    data_id = ""
    if res_upload.status_code == 200:
        data_id = res_upload.json()["data_id"] # get data id from response
        print(f"Uploading file: {file.name}")
    else: # error
        print("Error occurred when uploading file:", res_upload.status_code, res_upload.reason)
    return data_id

def get_result(data_id):
    """
    takes a data id, repeatedly pull results until scanning complete
    returns the response in json format
    returns empty dictionary if error occurred

    Str -> Dict
    """

    # url & headers for calling api
    url_result = f"https://api.metadefender.com/v4/file/{data_id}"
    header_result = {
        "apikey": api_key,
        # I actually didn't understand what "x-file-metadata" should be.
        # I use 0 since it gives a valid output. I'm not sure if it's the
        # correct value for this.
        "x-file-metadata": "0"
    }

    # get response
    res = requests.get(url_result, headers=header_result)
    start = time.time()

    if res.status_code == 200:
        # while value of scan_results.progress_percentage is smaller than 100 (process not complete)
        while res.json()['scan_results']['progress_percentage'] < 100:
            # sometimes it takes a long time to complete the process
            # it might be experiencing some time out here
            # if the process doesn't complete more than 30 seconds, display message and return empty result
            if time.time()-start > 30:
                print("(Error?) It takes longer than expected. Come back and try again later.")
                return {}
            print(f"Scanning file... {res.json()['scan_results']['progress_percentage']}%")
            time.sleep(3) # pull results every 3 seconds
            res = requests.get(url_result, headers=header_result)
            if res.status_code != 200:
                print("Error occurred during file scanning:", res.status_code, res.reason)
                return {}
        # return the response after process complete
        print(f"Scanning file... {res.json()['scan_results']['progress_percentage']}%")
        print("Finished scanning!")
        return res.json()
    else: # error
        print("Error occurred when fetching scanning results:", res.status_code, res.reason)
        return {}

def hash_lookup(file, api_key):
    """
    takes a file and api key, upload the file, perform a hash lookup
    returns the results of the lookup in json format
    returns empty dictionary if error occurred

    File, Str -> Dicts
    """

    # url & headers for calling api, using sha256 for lookup
    url_lookup = f"https://api.metadefender.com/v4/hash/{file.sha256}"
    header_lookup = {
        "apikey": api_key
    }

    # get response
    res_lookup = requests.get(url_lookup, headers=header_lookup)

    if res_lookup.status_code == 404: # results not found, upload the file
        data_id = upload_file(file, api_key)
        res = get_result(data_id)
        return res

    elif res_lookup.status_code == 200: # results found
        print("Results found!")
        return res_lookup.json()

    else: # error
        print("Error occurred during hash lookup:", res_lookup.status_code, res_lookup.reason)
        return {}

def display_results(res):
    """
    takes the results of the hash lookup
    prints the results in the same format as the sample format
    returns None

    Dict -> None
    """
    print("\nResults:")

    # empty results
    if not res:
        print("Results not found. Please refer to the error message above. ")
        return

    print(f"filename: {res['file_info']['display_name']}")
    print(f"overall_status: {res['scan_results']['scan_all_result_a']}")
    if not res["scan_results"]["scan_details"]:
        print("Scan details not found. ")
    else:
        for k, v in res["scan_results"]["scan_details"].items():
            print(f"engine: {k}")
            if v["threat_found"]:
                threat = v["threat_found"]
            else:
                threat = "Clean"
            print(f"threat_found: {threat}")
            print(f"scan_result: {v['scan_result_i']}")
            print(f"def_time: {v['def_time']}")
    return

# main
try:
    file_name = sys.argv[1]
    # create file object (& calculate hash)
    file = File(file_name)
except:
    print("Invalid input. Please check your input and try again. ")
    exit()

# hash lookup & get response
res = hash_lookup(file, api_key)

# display results
display_results(res)
