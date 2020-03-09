import subprocess
import re
import sys
import hashlib
import os


notes = []
valid_ids = []
pass_list = []
hash_list = []


def id_dump():
    print("Dumping LP Entry IDs")
    cmd = subprocess.Popen(["powershell", "-c", "bash -c 'lpass ls'"],
                           stdout=subprocess.PIPE, shell=True, universal_newlines=True)
    entries = cmd.communicate()[0]
    entries_list = entries.splitlines()
    # LastPass entries have a format of FolderName/EntryName [id: XXXX]. Folders are simply FolderName/ [id: XXX]
    # The following code checks for an EntryName and then pulls the corresponding ID #
    valid_ids_with_names = {}
    print("Removing folders and notes. Extracting only valid entry IDs")
    for line in entries_list:
        if re.findall('\S+/\S', line):
            valid_id = re.findall('id:\s([0-9.]+)', line)
            valid_ids.append(valid_id[0])
            valid_name = re.findall('\S*/([ -~]+)\s\[', line)
            valid_ids_with_names[valid_id[0]] = valid_name[0]
    print("Folders removed and IDs extracted. There are " + str(len(valid_ids)) + " entries to check.")
    # Time to loop through our valid IDs, grab the associated password, and check if the password key already exists.
    # We will create a dictionary like {'Password1': ['Entry1'], 'Password2': ['Entry2', 'Entry3']}


def password_extract(valid_ids_list):
    index = 0
    total_entries = len(valid_ids_list)
    while index < len(valid_ids_list):
        try:
            current_id = valid_ids_list[index]
            cmd = subprocess.Popen(["powershell", "-c", "bash -c 'lpass show " + current_id + "'"],
                                   stdout=subprocess.PIPE, shell=True, universal_newlines=True)
            full_entry = cmd.communicate()[0]
            entry_pass = re.findall('Password:\s([ -~]+)', full_entry, re.DOTALL)
            if len(entry_pass) == 0:
                notes.append(current_id)
                valid_ids_list.remove(current_id)
                total_entries -= 1
            else:
                entry_pass_str = entry_pass[0]
                if entry_pass_str in pass_list:
                    pass_list.append(entry_pass_str)
                    index += 1
                    if index % 10 == 0:
                        percent = str(((index / total_entries) * 100))
                        sys.stdout.write("\r" + '{0:5.5s}'.format(percent) + "% complete")
                else:
                    pass_list.append(entry_pass_str)
                    index += 1
                    if index % 10 == 0:
                        percent = str(((index / total_entries) * 100))
                        sys.stdout.write("\r" + '{0:5.5s}'.format(percent) + "% complete")
        except UnicodeDecodeError:
            print("Failed on " + current_id)
            sys.exit(1)


def pass_hash(pass_set):
    for password in pass_set:
        pass_hash = hashlib.sha256((password).encode('utf-8')).hexdigest()
        hash_list.append(pass_hash)
    print("Passwords hashed with SHA-256.")


def crack_hash(hashes):
    os.chdir(hashcat_dir)
    with open('hashes.hash', 'w') as f:
        for hash in hashes:
            f.write(hash + "\n")
    print("By default hashcat will be run with hashcat64.exe -a 0 -m 1400 hashes.hash example.dict -O")
    hashcat_options = input("Please enter your options EXACTLY as you want them (excluding hashcat executable, "
                            "hashmode, and attack mode. EG 'wordlist.dict -r ./rules/rockyou-30000.rule -O' \n")
    if hashcat_options == "":
        print("Running with default options.")
        cmd = subprocess.Popen(["powershell", "-c", "cd " + hashcat_dir + "; " + hashcat_dir + "hashcat64.exe -a 0 "
                            "-m 1400 hashes.hash example.dict -O"],
                           stdout=subprocess.PIPE, shell=True, universal_newlines=True)
        while True:
            hashcat_status = cmd.stdout.readline()
            if hashcat_status == '':
                break
            if hashcat_status:
                print(hashcat_status.strip())
    else:
        print("Running hashcat as 'hashcat64.exe -a 0 -m 1400 hashes.hash "
              + hashcat_options + "' This may take a VERY long time depending on options chosen.")
        cmd = subprocess.Popen(["powershell", "-c", "cd " + hashcat_dir + "; " + hashcat_dir + "hashcat64.exe -a 0 "
                            "-m 1400 hashes.hash " + hashcat_options], stdout=subprocess.PIPE,
                               shell=True, universal_newlines=True)
        while True:
            hashcat_status = cmd.stdout.readline()
            if hashcat_status == '':
                break
            if hashcat_status:
                print(hashcat_status.strip())


def weak_passwords():
    print("Printing bad passwords: \n")
    os.chdir(hashcat_dir)
    with open('hashcat.potfile', 'r') as f:
        for line in f:
            print(line)

if __name__ == '__main__':
    id_dump()
    password_extract(valid_ids)
    password_set = set(pass_list)
    pass_hash(password_set)
    print("There are " + len(password_set) + " unique passwords to check.")
    hashcat_dir = input("Please enter the full path to your hashcat install. IE 'E:/bin/hashcat-5.1.0/' "
                        "(Yes, please use forward and trailing slashes on Windows):")
    crack_hash(hash_list)
    print("Cracking complete")
    weak_passwords()