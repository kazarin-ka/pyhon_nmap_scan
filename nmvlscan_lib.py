#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import os
import subprocess
import wget

def error_exit(message):
    print(message)
    sys.exit(1)

# check that nmap has installed
def chk_nmap_instld():
    if not (os.path.exists("/usr/bin/nmap") and os.path.isfile("/usr/bin/nmap")):
        error_exit("Nmap tool is not installed!")
    else:
        return True


# check nmap version. It must be 7.40 or higher
def chk_nmap_ver(nmap_req_v):
    command = "nmap -V | grep version | cut -f 3 -d ' ' "
    nmap_instld_v = float(str(subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).communicate()[0])[2:6])
    if nmap_instld_v < float(nmap_req_v):
        error_exit("You have outdated nmap. Need version 7.40 or higher!")
    else:
        return True

# chech that script was downloaded. If not - download it!
def chk_script(dir, script_url, nse_script_name):

    if not (os.path.exists(dir + nse_script_name) and os.path.isfile(dir + nse_script_name)):
        current_dir = os.getcwd()
        os.chdir(dir)
        wget.download(script_url, nse_script_name)
        os.chdir(current_dir)
        return True

    else:
        return True

# check all conditions: nmap installed, nmap has correct version,
#                       there are the necessary folders and script downloaded.
def chk_nmap(nmap_req_v, dir1, dir2, script_url, nse_script_name):
    # check that nmap installed, has correct version and scipt directory created
    if (chk_nmap_instld() and chk_nmap_ver( nmap_req_v )):

        script_dir = [dir1, dir2]

        # check nmap script dir
        if (os.path.exists(script_dir[0]) and os.path.isdir(script_dir[0])):
            # check the script
           if chk_script(script_dir[0], script_url, nse_script_name):
               return True

        elif (os.path.exists(script_dir[1]) and os.path.isdir(script_dir[1])):
            if chk_script(script_dir[1], script_url, nse_script_name):
                return True

        else:
            error_exit("There isn't dir for nmap scripts!")


def print_help():
    print(" nmvlscan ip|network/mask - scan destination ip or network")

# check that we run this program in a first time.
# If so, we need to check for multiple conditions
#               - nmap installed
#               - it has correct version
#               - check script dirs
#               - check the script
def chk_first_run(flag):

    if not (os.path.exists(flag) and os.path.isfile(flag)):
        try:
            flag_file = open(flag, 'w')
            flag_file.write("OK")
            flag_file.close()

        except FileExistsError:
            error_exit("File Exists... (")
        except FileNotFoundError:
            error_exit("File Not Found... (")
        except PermissionError:
            error_exit("Not Enough Permission... (")
        except Exception:
            error_exit("Something went wrong... (")

        return True
    else:
        return False