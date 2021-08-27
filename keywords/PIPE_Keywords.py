import random
import signal
import subprocess
from zipfile import ZipFile

import time

from Helpers.Logger import Logger, log
import Helpers.pipe_helper
import string
from Helpers.KmiHelper import *
from Helpers.AuxHelper import AuxHelper


pki_proc = None
pipe_helper = None

#####################################################
#                     PIPE KMI Keywords             #
#####################################################


def pipe_add_oper():
    add_operator(pipe_helper)
    go_to_main_menu()


def pipe_import_manifacturing_report(file_name, manuf_name, comment):
    try:
        return import_manufacturing_report(pipe_helper, str(file_name).lower(), str(manuf_name).lower(), str(comment))
    except Exception, e:
        log('ERROR in pipe_import_manifacturing_report: %s' % e)
        return 0
    finally:
        # go_to_main_menu()
        close_console()


def pipe_linck_black_box_to_pttp():
    try:
        link_pttp_to_blackbox(pipe_helper)
    except Exception, e:
        log('ERROR in pipe_linck_black_box_to_pttp: %s' % e)
    finally:
        go_to_main_menu()


def pipe_encrypt_ssl_certificates(ssl_type, devcl, pttp_link_partnumber, security_constants, key_index,
                                  manufacturer, filename):
    try:
        return encrypt_ssl_certificates(pipe_helper, str(ssl_type), str(devcl),
                                                      str(pttp_link_partnumber),
                                                      str(security_constants), str(key_index), str(manufacturer),
                                                      str(filename))
    except Exception, e:
        log('ERROR in pipe_encrypt_ssl_certificates: %s' % e)
        return 0
    finally:
        go_to_main_menu()


def pipe_export_pgp_key():
    try:
        return export_pgp_key_for_user(pipe_helper)
    except Exception, e:
        log('ERROR in pipe_export_pgp_key: %s' % e)
        return 0
    finally:
        go_to_main_menu()


def pipe_add_public_pgp_key(user_name, key_name):
    try:
        add_public_pgp(pipe_helper, str(user_name), str(key_name))
    except Exception, e:
        log('ERROR in pipe_add_public_pgp_key: %s' % e)
        return 0
    finally:
        go_to_main_menu()

def pipe_export_frimware_key_with_hash(blbx_name):
    try:
        return export_frimware_key_with_hash(pipe_helper, blbx_name)
    except Exception, e:
        log('ERROR in pipe_export_frimware_key_with_hash: %s' % e)
    finally:
        go_to_main_menu()

def pipe_export_otp_key_with_hash(count_device):
    try:
        return export_otp_key_with_hash(pipe_helper, count_device)
    except Exception, e:
        log('ERROR in pipe_export_otp_key')
    finally:
        go_to_main_menu()

def pipe_prepare_drm_keys_with_hash(count_device):
    try:
        return prepare_drm_keys_with_hash(pipe_helper, count_device)
    except Exception, e:
        log('ERROR in prepare drm keys with hash')
    finally:
        go_to_main_menu()

def pipe_prepare_drm_keys_from_ext_file(partner_id,filename, keyindex, operation_type, encrypt_type, namefilekeys, namefileconfig,
                                   secondkeyindex = None, second_operation_type = None, second_encrypt_type = None):
    try:
        return prepare_drm_keys_from_ext_file(pipe_helper, partner_id, filename, keyindex, operation_type, encrypt_type, namefilekeys, namefileconfig, secondkeyindex, second_operation_type, second_encrypt_type)
    except Exception, e:
        log('ERROR in prepare drm keys from ext file')
    finally:
        close_console()

def pipe_link_firmware_keys_to_otp(dvcl, ptnb, key_algorithm, key_length, key_code, key_index, key_privacy, key_fragment):
    try:
        return link_firmware_keys_to_otp(pipe_helper, dvcl, ptnb, key_algorithm, key_length, key_code, key_index, key_privacy, key_fragment)
    except:
        log('Error in link firmware keys to otp')

def pipe_edit_common_aux_keyset_name(lest_id, name):
    try:
        return edit_common_aux_keyset_name(pipe_helper, lest_id, name)
    except:
        log('Error in edit_common_aux_keyset_name')
    finally:
        go_to_main_menu()

def pipe_add_firmware_keys_values(dvcl, ptnb, key_name, key_type, exponent, filename=None):
    try:
        return add_firmware_keys_values(pipe_helper, dvcl, ptnb, key_name, key_type, exponent, filename)
    except:
        log('Error in add_firmware_keys_values')
    finally:
        go_to_main_menu()

def pipe_clone_aux_keys_sets(aux_key_type, new_aux_keys_name, aux_type, dvcl_id, ptnb_id, auxkeys_id, second_dvcl_id = None, second_ptnb_id = None):
    try:
        return clone_aux_keys_sets(pipe_helper, aux_key_type, new_aux_keys_name, aux_type, dvcl_id, ptnb_id, auxkeys_id,  second_dvcl_id, second_ptnb_id)
    except Exception as e:
        print e
        log('ERROR in clone_aux_keys_sets')
    finally:
        go_to_main_menu()

#######################################################################
#######################################################################
def prepare_filename_drm_archive(pttp_id, partner_name):
    return '%s_%08X_drm-keys.zip.gpg' % (partner_name, int(pttp_id))

def randoname(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(int(length)))

def unzip_file(path):
    zip = ZipFile(path)
    path_out = get_homedir_out()
    zip.extractall(path_out)


def __get_key_by_value_from_dict(dict, value):
    val = dict.keys()[dict.values().index(value.lower())]
    return val

def __get_key_by_part_value_from_dict(dict, value):
    for item in dict:
        if value.lower() in dict[item]:
            return item

def __get_id_by_value_from_list_dicts(list_dicts, value):
    for dict in list_dicts:
        ans = __get_key_by_part_value_from_dict(dict, value.lower())
        if ans:
            for item in dict.keys():
                if item.endswith('id'):
                    return dict[item]

def go_to_main_menu():
    global pipe_helper
    while 'Key Management Infrastructure Console' not in pipe_helper.menu.title:
        pipe_helper.send_to_pipe('', signal.SIGINT)

def run_console():
    global pki_proc, pipe_helper
    if pki_proc is None:
        pki_proc = subprocess.Popen('python  -u /opt/kmi/console/kmi_console.py',
                                shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        pipe_helper = Helpers.pipe_helper.Pipehelper(pki_proc)


def close_console():
    global pki_proc, pipe_helper
    pki_proc.kill()
    pki_proc = None

def add_operator(pipe_helper):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0],'management'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0],'operators'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'add operator'))
    pipe_helper.send_to_pipe('12345')
    pipe_helper.send_to_pipe('')

def import_manufacturing_report(pipe_helper, file_name, manufacturing_name, comment):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'working with reports'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'import stb manufacturing report'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], manufacturing_name))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe(__get_key_by_part_value_from_dict(pipe_helper.menu.items[0], file_name))
    pipe_helper.send_to_pipe(comment)
    pipe_helper.send_to_pipe('y')
    pipe_helper.send_to_pipe('')


def link_pttp_to_blackbox(pipe_helper):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'management'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'part types'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'link black box to part type'))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'first_parttype'))

def encrypt_ssl_certificates(pipe_helper, ssl_type, devcl, pttp_link_partnumber, security_constants, key_index, manufacturer, filename):
    print ssl_type, devcl, pttp_link_partnumber, security_constants, key_index, manufacturer, filename
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'third party systems integration'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'encrypt ssl certificates'))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, ssl_type))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, devcl))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, pttp_link_partnumber))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, security_constants))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], key_index))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], manufacturer))
    pipe_helper.send_to_pipe(__get_key_by_part_value_from_dict(pipe_helper.menu.items[0], 'current user'))
    pipe_helper.send_to_pipe(__get_key_by_part_value_from_dict(pipe_helper.menu.items[0], 'encrypt by all keys'))
    pipe_helper.send_to_pipe(__get_key_by_part_value_from_dict(pipe_helper.menu.items[0], filename))

def export_pgp_key_for_user(pipe_helper):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'service and settings'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'user pgp keys'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'generate pgp key pair'))
    pipe_helper.send_to_pipe('n')
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'jenkins'))
    pgp_name = random.randint(0,9999999999999)
    pipe_helper.send_to_pipe(str(pgp_name))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'export public pgp key'))
    pipe_helper.send_to_pipe('n')
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'jenkins'))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, str(pgp_name)))
    default_key_name = pipe_helper.menu.items[0]
    pipe_helper.send_to_pipe('')
    default_key_name = (default_key_name.split(':'))[1]
    key_name = (default_key_name.split(']'))[0]
    return key_name.strip()

def add_public_pgp(pipe_helper, user_name, key_name):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'service and settings'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'user pgp keys'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'import public pgp key'))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, str(user_name)))
    pipe_helper.send_to_pipe(__get_key_by_part_value_from_dict(pipe_helper.menu.items[0], str(key_name)))
    return 1

def export_frimware_key_with_hash(pipe_helper, blbx_name):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'working with otp/firmware keys'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'export firmware keys to sign server'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], blbx_name.lower()))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, 'deviceclasswithfw'))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, 'partnumberwithfw'))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe('n')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('0')
    return '2_key_ladder_hash'


def export_otp_key_with_hash(pipe_helper, count_devices):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'working with otp/firmware keys'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'export otp keys'))
    pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe(count_devices)
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'bb'))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('n')
    pipe_helper.send_to_pipe('y')
    return '1_key_ladder_hash'

def prepare_drm_keys_with_hash(pipe_helper, count_devices):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'third party systems integration'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'prepare drm keys'))
    pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'unique_128'))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe(count_devices)
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'decrypt'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'tde encryption'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'mysignserver'))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe('')
    return '2_key_ladder_hash'

def prepare_drm_keys_from_ext_file(pipe_helper, partner_id, filename, keyindex, operation_type, encrypt_type, namefilekeys, namefileconfig,
                                   secondkeyindex, second_operation_type, second_encrypt_type):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'third party systems integration'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'prepare drm keys from external list'))
    pipe_helper.send_to_pipe(__get_key_by_part_value_from_dict(pipe_helper.menu.items[0], str(filename)))
    pipe_helper.send_to_pipe(str(partner_id))
    # pipe_helper.send_to_pipe('1')
    pipe_helper.send_to_pipe(str(keyindex))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], str(operation_type)))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], str(encrypt_type)))
    if encrypt_type == 'tde encryption':
        pipe_helper.send_to_pipe('2')
    if secondkeyindex is not None:
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items, str(secondkeyindex)))
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items, str(second_operation_type)))
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items, str(second_encrypt_type)))
        if encrypt_type == 'tde encryption':
            pipe_helper.send_to_pipe('2')
    pipe_helper.send_to_pipe(str(namefileconfig))
    pipe_helper.send_to_pipe(str(namefilekeys))
    pipe_helper.send_to_pipe('0')
    for item in pipe_helper.menu.items:
        if 'Error: Preparing DRM keys failed:' in item:
            return 0
    return 1

def link_firmware_keys_to_otp(pipe_helper, dvcl, ptnb, key_algorithm, key_length, key_code, key_index, key_privacy, key_fragment):
    try:
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'management'))
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'firmware keys'))
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'add firmware keys descriptions'))
        pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, dvcl))
        pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, ptnb))
        pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_algorithm))
        pipe_helper.send_to_pipe(key_length)
        pipe_helper.send_to_pipe(key_code)
        pipe_helper.send_to_pipe('y')
        pipe_helper.send_to_pipe(key_index)
        if key_algorithm == 'rsa':
            # pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_privacy))
            pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_fragment))
            pipe_helper.send_to_pipe(0)
        pipe_helper.send_to_pipe(0)
        go_to_main_menu()
        return 1
    except Exception as E:
        return E

def edit_common_aux_keyset_name(pipe_helper, lest_id, name):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'management'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'auxiliary keysets'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'edit common aux keyset'))
    pipe_helper.send_to_pipe('')
    pipe_helper.send_to_pipe(lest_id)
    pipe_helper.send_to_pipe(name)
    return 1

def add_firmware_keys_values(pipe_helper, dvcl, ptnb, key_name, key_type, exponent, filename):
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'Working with OTP/Firmware keys'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'Add Firmware keys values'))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, dvcl))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, ptnb))
    pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_name))
    # pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], key_type))
    if key_type == 'generate':
        pipe_helper.send_to_pipe(1)
        pipe_helper.send_to_pipe(exponent)
    elif key_type == 'import':
        pipe_helper.send_to_pipe(__get_key_by_part_value_from_dict(pipe_helper.menu.items[0], str(filename)))
        pipe_helper.send_to_pipe(0)
    pipe_helper.send_to_pipe(0)
    return 1

def link_2_firmware_keys_to_otp(pipe_helper, dvcl, ptnb, key_algorithm, key_length, key_code, key_index, key_privacy, key_fragment):
    try:
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'management'))
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'firmware keys'))
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'add firmware keys descriptions'))
        pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, dvcl))
        pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, ptnb))
        pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_algorithm))
        pipe_helper.send_to_pipe(key_length)
        pipe_helper.send_to_pipe(key_code)
        pipe_helper.send_to_pipe('y')
        pipe_helper.send_to_pipe(key_index)
        if key_algorithm == 'rsa':
            # pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_privacy))
            pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_fragment))
            pipe_helper.send_to_pipe(1)
        pipe_helper.send_to_pipe(key_index)
        pipe_helper.send_to_pipe(__get_id_by_value_from_list_dicts(pipe_helper.menu.items, key_fragment))
        pipe_helper.send_to_pipe(0)
        pipe_helper.send_to_pipe(0)
        go_to_main_menu()
        return 1
    except Exception as E:
        return E

def clone_aux_keys_sets(pipe_helper, aux_key_type, new_aux_keys_name, aux_type, dvcl_id, ptnb_id, auxkeys_id, second_dvcl_id, second_ptnb_id):
    if second_dvcl_id is None:
        second_dvcl_id = dvcl_id
    if second_ptnb_id is None:
        second_ptnb_id = ptnb_id
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'management'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'auxiliary keysets'))
    pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], 'Clone Common Aux KeySet'))
    pipe_helper.send_to_pipe(dvcl_id)
    pipe_helper.send_to_pipe(ptnb_id)
    pipe_helper.send_to_pipe(auxkeys_id)
    pipe_helper.send_to_pipe(second_dvcl_id)
    pipe_helper.send_to_pipe(second_ptnb_id)
    if aux_key_type == 2:
        pipe_helper.send_to_pipe(__get_key_by_value_from_dict(pipe_helper.menu.items[0], aux_type))
    if new_aux_keys_name == 'default':
        pipe_helper.send_to_pipe('')
    else:
        pipe_helper.send_to_pipe(new_aux_keys_name)
    pipe_helper.send_to_pipe('')
    return 1
