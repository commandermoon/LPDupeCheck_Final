import subprocess
import re
import sys
import time


notes = []
pass_and_entry = {}


def password_extract(valid_ids, total_entries):
    index = 0
    current_id = ""
    while index < len(valid_ids):
        try:
            current_id = valid_ids[index]
            cmd = subprocess.Popen(["powershell", "-c", "bash -c 'lpass show " + current_id + "'"],
                                   stdout=subprocess.PIPE, shell=True, universal_newlines=True)
            full_entry = cmd.communicate()[0]
            entry_pass = re.findall('Password:\s([ -~]+)', full_entry, re.DOTALL)
            if len(entry_pass) == 0:
                notes.append(current_id)
                valid_ids.remove(current_id)
                total_entries -= 1
            else:
                entry_pass_str = entry_pass[0]
                if entry_pass_str in pass_and_entry.keys():
                    pass_and_entry[entry_pass_str].append(current_id)
                    index += 1
                    if index % 10 == 0:
                        percent = str(((index / total_entries) * 100))
                        sys.stdout.write("\r" + '{0:5.5s}'.format(percent) + "% complete")
                else:
                    pass_and_entry[entry_pass_str] = [current_id]
                    index += 1
                    if index % 10 == 0:
                        percent = str(((index / total_entries) * 100))
                        sys.stdout.write("\r" + '{0:5.5s}'.format(percent) + "% complete")
        except UnicodeDecodeError:
            print("Failed on " + current_id)
            sys.exit(1)


def main():
    print("Starting time: " + time.asctime())
    print("This tool will check your entire LastPass database for duplicate passwords. Note: This is intended for "
          "shared accounts which are not included in the built-in Security Challenge check. This will take quite"
          " some time.")
    print("Checking if you have the necessary pre-reqs.")
    print("Pre-req check started at " + time.asctime())
    cmd = subprocess.Popen(["powershell.exe", "-c", "bash -c 'uname'"], stdout=subprocess.PIPE, shell=True,
                           universal_newlines=True)
    wsl_check = cmd.communicate()[0]
    if wsl_check == "":
        print("You either don't have the Windows Subsytem for Linux installed or you need to install a Linux distro. "
              "Please enable WSL via Powershell with "
              "'Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux' "
              "Then install a distro via the Microsoft Store and initialze the install.")
    else:
        cmd = subprocess.Popen(["wsl.exe", "-e", "lpass"], stdout=subprocess.PIPE, shell=True, universal_newlines=True)
        lpass_check = cmd.communicate()[0]
        if lpass_check == "":
            print("You don't have LastPass CLI installed.")
        elif lpass_check != "":
            cmd = subprocess.Popen(["powershell", "-c", "bash -c 'lpass status'"], stdout=subprocess.PIPE, shell=True,
                                   universal_newlines=True)
            login_check = cmd.communicate()[0]
            print("Your status: " + login_check)
            if login_check.rstrip() == "Not logged in.":
                exit()
    # If all pre-reqs have been passed, we begin dumping the IDs of all LastPass entries
    print("Pre-req check completed at " + time.asctime())
    print("Dumping LP Entry IDs")
    print("Starting entry dump at " + time.asctime())
    cmd = subprocess.Popen(["powershell", "-c", "bash -c 'lpass ls'"],
                           stdout=subprocess.PIPE, shell=True, universal_newlines=True)
    entries = cmd.communicate()[0]
    entries_list = entries.splitlines()
    print("Entry dump completed at " + time.asctime())
    # LastPass entries have a format of FolderName/EntryName [id: XXXX]. Folders are simply FolderName/ [id: XXX]
    # The following code checks for an EntryName and then pulls the corresponding ID #
    valid_ids = []
    valid_ids_with_names = {}
    print("Removing folders and notes. Extracting only valid entry IDs")
    print("Valid ID extraction started at " + time.asctime())
    for line in entries_list:
        if re.findall('\S+/\S', line):
            valid_id = re.findall('id:\s([0-9.]+)', line)
            valid_ids.append(valid_id[0])
            valid_name = re.findall('\S*/([ -~]+)\s\[', line)
            valid_ids_with_names[valid_id[0]] = valid_name[0]
    print("Valid ID extraction completed at " + time.asctime())
    total_entries = len(valid_ids)
    print("Folders removed and IDs extracted. There are " + str(total_entries) + " entries to check.")
    # Time to loop through our valid IDs, grab the associated password, and check if the password key already exists.
    # We will create a dictionary like {'Password1': ['Entry1'], 'Password2': ['Entry2', 'Entry3']}
    print("Extracting passwords")
    print("Starting password extraction at " + time.asctime())
    password_extract(valid_ids, total_entries)
    print("Password extraction ended at " + time.asctime())
    # Replacing entry IDs with names for readability.
    final_dict = {}
    print("Started final ID to name conversion at " + time.asctime())
    for entry_password, entry_id in pass_and_entry.items():
        if len(entry_id) > 1:
            for list_id in entry_id:
                if entry_password in final_dict.keys():
                    final_dict[entry_password].append(valid_ids_with_names[list_id])
                else:
                    name = valid_ids_with_names[list_id]
                    final_dict[entry_password] = [name]
    print("ID to name conversion finished at " + time.asctime())
    final_notes = []
    for note in notes:
        final_notes.append(valid_ids_with_names[note])
    for key in final_dict:
        print("The following accounts all share a password: " + str(final_dict[key]) +
              ". These should be reviewed and changed.")
    print("Please also check these notes: " + str(final_notes))
    print("End time: " + time.asctime())


if __name__ == '__main__':
    main()
