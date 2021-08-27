import ftplib
from KmiHelper import *
import gnupg
import time

class FTP_conn(object):
    def __init__(self):
        self.con = ftplib.FTP()

    def copy_ftp(self, filename, type):
        if type == "to":
            path_on_ftp = '/'.join(get_homedir_in().split('/')[-2:])
            self.con.cwd(path_on_ftp)
            try:
                self.con.storbinary("STOR %s" % 'copy_' + filename.split('/')[-1], open(filename, "rb"))
            except Exception, e:
                print e
            return filename.split('/')[-1]

        else:
            home_path = get_homedir_out()
            path_on_ftp = '/'.join(home_path.split('/')[-2:])
            self.con.cwd(path_on_ftp)
            try:
                with open(home_path + '/' + filename, 'wb') as local_file:
                    self.con.retrbinary('RETR %s' % filename, local_file.write)
            except Exception as e:
                print('ERORR'), e
            return home_path + '/' + filename


def encrypt_file(path_to_key, filename):
    path_to_file = get_homedir_in() + '/' + filename
    gpg = gnupg.GPG()
    #while gpg.list_keys().fingerprints[0] != None:
    #    print gpg.list_keys().fingerprints
    print gpg.delete_keys(gpg.list_keys().fingerprints)
    key_data = open(path_to_key).read()
    gpg.import_keys(key_data)
    public_keys = gpg.list_keys()
    print public_keys
    message = open(path_to_file, 'rb').read()
    gpg.encrypt(message, public_keys.fingerprints[0], armor=False, output=path_to_file + '.gpg')
    return path_to_file + '.gpg'

def decrypt_file(path_to_key, filename):
    cur_dir = os.getcwd()
    home_dir = '/' + '/'.join(cur_dir.split('/')[1:3])
    if filename[-4:] == '.gpg':
        filename = filename[:-4]
    path_to_clear_file = get_homedir_out() + '/' + filename
    # path_to_file = filename + '.gpg'
    path_to_file = path_to_clear_file + '.gpg'
    print path_to_key
    gpg = gnupg.GPG()
    gpg.delete_keys(gpg.list_keys().fingerprints)
    # key_data_priv = open(home_dir + '/kmi_tests/data_helper/test_key/secret_key.gpg').read()
    key_data_priv = open(path_to_key).read()
    gpg.import_keys(key_data_priv)
    file_data = open(str(path_to_file), 'r')
    decrypt = gpg.decrypt_file(file_data, always_trust=True, passphrase=None, output=str(path_to_clear_file))
    return path_to_clear_file