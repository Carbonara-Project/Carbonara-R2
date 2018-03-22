from guanciale import *
import progressbar
import appdirs
import requests
import getpass
import os
import sys

dirs = appdirs.AppDirs("carbonara_cli")
token_path = os.path.join(os.path.dirname(dirs.user_config_dir), "carbonara_cli.token")

CARBONARA_URL = "https://carbonaraproject.com"
#CARBONARA_URL = "http://localhost:8000"
CLIENT_ID="2MBBuSf2kKNhHyDMjKi80jJPeJqzhYdzsOxzHM3z"

token = None

def get_token():
    global token
    
    request_token = False
    try:
        token_file = open(token_path)
        token = token_file.read()
        token_file.close()
    except:
        request_token = True

    #verify token
    if request_token == False:
        done = False
        headers = {"Authorization": "Bearer " + token}
        try:
            r = requests.head(CARBONARA_URL + "/api/program/", headers=headers)
            done = True
            #print r
        except:
            request_token = True
        
        if done:
            if r.status_code == 401 or r.status_code == 403: #token expired
                request_token = True
            elif r.status_code != 400 and r.status_code != 200 and r.status_code != 204:
                return "cannot verify auth token"
                request_token = True
    
    if request_token:
        print LCYAN + " >> Login to Carbonara " + NC
        username = raw_input("Username: ")
        password = getpass.getpass("Password: ")
        auth_body = {
            "client_id": CLIENT_ID,
            "grant_type": "password",
            "username": username,
            "password": password
        }
        try:
            r = requests.post(CARBONARA_URL + "/users/o/token/", data=auth_body)
        except:
            return "cannot get auth token"
        
        if r.status_code != 200:
            return "cannot get auth token"
        token = r.json()["access_token"]
    
    if token == None:
        return "wrong authentication"
    
    try:
        token_file = open(token_path, "w")
        token_file.write(token)
        token_file.close()
    except:
        printwarn("cannot save auth token")
        pass




def exists(md5):
    err = get_token()
    if err:
        printerr(err)
        exit(1)
    
    headers = {"Authorization": "Bearer " + token}
    try:
        r = requests.head(CARBONARA_URL + "/api/program/?md5=" + md5, headers=headers)
    except Exception as ee:
        print ee
        printerr("failed to connect to Carbonara")
        exit(1)
    if r.status_code == 404:
        return False
    elif r.status_code == 200 or r.status_code == 204:
        return True
    else:
        printerr("invalid response")
        exit(1)


def printusage():
    print LMAG_BG + "  usage  " + NC + LMAG + " radare2> " + NC + "#!pipe carbr2 [OPTIONS]"
    print
    print "OPTIONS:"
    print "   -h, --help                          show this help"
    print "   -e, --exists                        check if the current opened file is already on the server"
    print "   -p, --proc <name/offset>            analyze only a procedure and upgrade it's info on the server"
    print "   -r, --rename                        rename each procedure in the binary with the name of a similar procedure in our server if the matching treshold is >= TRESHOLD"
    print "   -pr, --proc-rename <name/offset>    rename a single procedure if the matching treshold is >= TRESHOLD"
    print "   -t, --treshold <int>                set TRESHOLD (optional, default 90)"
    print

def main():
    #report status on stdout using a progressbar
    class ProgressBarStatus(status.Status):
        def __init__(self, maxval):
            self.pgbar = progressbar.ProgressBar(redirect_stdout=True, max_value=maxval)
        
        def update(self, num):
            self.pgbar.update(num)
            
        def __enter__(self):
            return self.pgbar.__enter__()

        def __exit__(self, type, value, traceback):
            self.pgbar.__exit__(type, value, traceback)

    status.Status = ProgressBarStatus

    args = {"treshold": 90}
    haserr = False

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "-h" or sys.argv[i] == "--help":
            printusage()
            exit(0)
        elif sys.argv[i] == "-e" or sys.argv[i] == "--exists":
            args["exists"] = 1
        elif sys.argv[i] == "-p" or sys.argv[i] == "--proc":
            if i == len(sys.argv) -1:
                printerr("arg '--proc': expected one argument")
                exit(1)
            args["proc"] = sys.argv[i+1]
            i += 1
        elif sys.argv[i] == "-pr" or sys.argv[i] == "--proc-rename":
            if i == len(sys.argv) -1:
                printerr("arg '--proc-rename': expected one argument")
                exit(1)
            args["proc-rename"] = sys.argv[i+1]
            i += 1
        elif sys.argv[i] == "-r" or sys.argv[i] == "--rename":
            args["rename"] = 1
        elif sys.argv[i] == "-t" or sys.argv[i] == "--treshold":
            if i == len(sys.argv) -1:
                printerr("arg '--treshold': expected one argument")
                exit(1)
            try:
                args["treshold"] = int(sys.argv[i+1])
            except:
                printerr("arg '--treshold': the argument must be a number")
                haserr = True
            i += 1
        else:
            printerr("arg '%s': not recognized" % sys.argv[i])
            haserr = True
        i += 1

    if haserr:
        exit(1)

    try:
        bi = BinaryInfo(R2PLUGIN)
    except IOError as err:
        printerr(err)
        exit(1)
    except Exception as err:
        printerr(err)
        exit(1)

    def analyzeAll():
        bi.addAdditionalInfo()
        bi.addStrings()
        bi.grabProcedures("radare2")
        
        data = bi.processAll()
        
        err = get_token()
        if token:
            headers = {"Authorization": "Bearer " + token}
            binfile = open(bi.filename, "rb")
            try:
                print(" >> Uploading to Carbonara...")
                remain = []
                if len(data["procs"]) > 16:
                    remain = data["procs"][16:]
                    data["procs"] = data["procs"][:16]
                
                r = requests.post(CARBONARA_URL + "/api/report/", headers=headers, files={
                    "binary":(os.path.basename(bi.filename), binfile.read()),
                    "report":json.dumps(data)
                    })
                if r.status_code != 200:
                    print r.content
                    err = True
                else:
                    while len(remain) > 0:
                        if len(remain) > 16:
                            remain = remain[16:]
                            data["procs"] = remain[:16]
                        else:
                            remain = []
                            data["procs"] = remain
                        
                        r = requests.post(CARBONARA_URL + "/api/procs-report/", headers=headers, files={
                        "report":json.dumps({
                            "md5": data["program"]["md5"],
                            "procs": data["procs"]
                            })
                        })
                        if r.status_code != 200:
                            print r.content
                            err = True
                            break
            except:
                err = True
            binfile.close()
        if err:
            if err != True:
                printwarn(err)
            fname = os.path.basename(bi.filename) + ".analysis.json"
            printwarn("failed to upload to Carbonara, the output will be saved in a file (" + fname + ")")
            outfile = open(fname, "w")
            outfile.write(data)
            outfile.close()

    if "proc-rename" in args:
        if not exists(bi.md5):
            print " >> The binary is not present in the server, so it must be analyzed."
            analyzeAll()
        else:
            print " >> The binary is already on the server"
            bi.grabProcedures("radare2")
        
        cmds = []
       
        pname = args["proc-rename"]
        try:
            paname = int(pname, 16)
        except: pass
       
        for i in xrange(0, len(bi.procs)):
            p = bi.procs[i]
            if type(pname) == int and p["offset"] != pname: continue
            if type(pname) == str and p["name"] != pname: continue
            
            procs_dict = {}
            
            payload = {}
            
            payload[bi.md5+":"+str(p["offset"])] = 3
            procs_dict[p["offset"]] = p["name"]
            max_proc_name = len(p["name"])
            
            r = None
            headers = {"Authorization": "Bearer " + token}
            err=False
            try:
                print(" >> Querying Carbonara...")
                r = requests.post(CARBONARA_URL + "/api/simprocs/", headers=headers, json=payload)
                if r.status_code != 200:
                    print r.content
                    err = True
            except Exception as ee:
                #print ee
                err = True
            if err:
                printwarn("cannot get simprocs")
                continue
            
            resp = r.json()
            
            for k in resp:
                if len(resp[k]) == 0:
                    continue
                off = int(k.split(":")[1])
                
                for r in resp[k]:
                    if r["match"] >= args["treshold"]:
                        if (not r["name"].startswith("fcn.")) and (hex(r["offset"])[2:] not in r["name"]) and (not r["name"].startswith("sub_")) and (hex(r["offset"])[2:] not in r["name"]):
                            print procs_dict[off] + " " * (max_proc_name - len(procs_dict[off])) + " --> " + r["name"] + "\t(" + r["md5"] + ":" + hex(r["offset"]) + ")"
                            cmds.append("afn " + r["name"] + " " + hex(off))
                            break
                    else:
                        break
        
        print
        a = raw_input(" >> Do you accept renaming? (Y, n): ")
        if a == "" or a.lower() == "y":
            for c in cmds:
                bi.r2.cmd(c)
            
        exit(0)      
    if "rename" in args:
        if not exists(bi.md5):
            print " >> The binary is not present in the server, so it must be analyzed."
            analyzeAll()
        else:
            print " >> The binary is already on the server"
            bi.grabProcedures("radare2")
        
        cmds = []
               
        for i in xrange(0, len(bi.procs), 16):
            procs_dict = {}
            max_proc_name = 0
            
            payload = {}
            
            for j in xrange(i, i+16):
                if j >= len(bi.procs):
                    break
                p = bi.procs[j]
                payload[bi.md5+":"+str(p["offset"])] = 3
                procs_dict[p["offset"]] = p["name"]
                max_proc_name = max(max_proc_name, len(p["name"]))
            
            r = None
            headers = {"Authorization": "Bearer " + token}
            err=False
            try:
                print(" >> Querying Carbonara...")
                r = requests.post(CARBONARA_URL + "/api/simprocs/", headers=headers, json=payload)
                if r.status_code != 200:
                    print r.content
                    err = True
            except Exception as ee:
                #print ee
                err = True
            if err:
                printwarn("cannot get simprocs")
                continue
            
            resp = r.json()
            
            for k in resp:
                if len(resp[k]) == 0:
                    continue
                off = int(k.split(":")[1])
                
                for r in resp[k]:
                    if r["match"] >= args["treshold"]:
                        if (not r["name"].startswith("fcn.")) and (hex(r["offset"])[2:] not in r["name"]) and (not r["name"].startswith("sub_")) and (hex(r["offset"])[2:] not in r["name"]):
                            print procs_dict[off] + " " * (max_proc_name - len(procs_dict[off])) + " --> " + r["name"] + "\t(" + r["md5"] + ":" + hex(r["offset"]) + ")"
                            cmds.append("afn " + r["name"] + " " + hex(off))
                            break
                    else:
                        break
        
        print
        a = raw_input(" >> Do you accept renaming? (Y, n): ")
        if a == "" or a.lower() == "y":
            for c in cmds:
                bi.r2.cmd(c)
            
        exit(0)


    if "exists" in args:
        if exists(bi.md5):
            print LCYAN + " >> Result: " + CARBONARA_URL + "" + NC
        else:
            print LCYAN + " >> The binary is not present in the Carbonara server." + NC
        exit(0)

    if "proc" not in args:
        analyzeAll()
    else:
        bi.grabProcedures("radare2")
        pdata = bi.processSingle(args["proc"])
        if pdata == None:
            printerr("procedure not found")
            exit(1)
        err = get_token()
        if token:
            #TODO chech status code
            headers = {"Authorization": "Bearer " + token}
            try:
                r = requests.post(CARBONARA_URL + "/api/procedure/update/", headers=headers, files={"report":json.dumps(data)})
                if r.status_code != 200:
                    err = True
            except:
                err = True
        if err:
            if err != True:
                printwarn(err)
            fname = os.path.basename(bi.filename) + "_" + hex(pdata["procedure"]["offset"]) + ".procedure.json"
            printwarn("failed to upload to Carbonara, the output will be saved in a file (" + fname + ")")
            outfile = open(fname, "w")
            outfile.write(data)
            outfile.close()

if __name__ == "__main__":
    main()











