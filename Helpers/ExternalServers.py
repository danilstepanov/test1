from KmiHelper import *
from KeyLadder import *

param_for_iv = ''

def create_empty_file_by_size(filename, filesize_by_byte):
    path_to_file = get_homedir_in() + '/' + filename
    path_to_enc_file = get_homedir_out() + '/' + filename + '.tde'
    if 'wrongpath' in filename:
        return (path_to_file,path_to_enc_file, None)
    else:
        open(path_to_file, 'w').truncate(filesize_by_byte)
        data = open(path_to_file).read()
        return (path_to_file,path_to_enc_file, data)

def check_encrypted_data_by_ext_server_keyladder(db, path_to_enc_file, data, ext_server_id):
    kl = KeyLadder(db)
    enc_data = open(path_to_enc_file).read()
    decrypt_data = kl.decrypt_buf_by_extsrv(enc_data, ext_server_id, param_for_iv.decode('hex'))
    assert(data == decrypt_data), 'ERROR data does not match'
    return 1

