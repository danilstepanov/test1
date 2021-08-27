from DB_ORM_classes import *
import random, os
from Logger import log
import Helpers.KeyLadder as KL
from KmiHelper import *
from Crypto.PublicKey import RSA


def get_test_pttp(sqlconnection, obfuscation=-1):
    test_pttp_ids_without_fw_value = list(set(sqlconnection.session.query(PartType.pttp_id).filter(PartType.is_test_pttp == 1, PartType.pttp_id == FirmwareKey.pttp_pttp_id, FirmwareKey.key_value == None).all()))
    pttp_with_fw_desc = list(set(sqlconnection.session.query(FirmwareKey.pttp_pttp_id).all()))
    if obfuscation == -1:
        test_pttp_ids = list(set(sqlconnection.session.query(PartType.pttp_id).filter(~PartType.pttp_id.in_(test_pttp_ids_without_fw_value),PartType.pttp_id.in_(pttp_with_fw_desc), PartType.is_test_pttp == 1, PartType.pttp_id == PartTypeKey.pttp_pttp_id, PartTypeKey.key_value != None).all()))
    else:
        test_pttp_ids = list(set(sqlconnection.session.query(PartType.pttp_id).filter(~PartType.pttp_id.in_(test_pttp_ids_without_fw_value),PartType.pttp_id.in_(pttp_with_fw_desc), PartType.is_test_pttp == 1, PartType.kof_kof_id == obfuscation, PartType.pttp_id == PartTypeKey.pttp_pttp_id, PartTypeKey.key_value != None).all()))
    pttp_id = random.choice(test_pttp_ids)[0]
    log('get_test_pttp return %s' % pttp_id)
    return pttp_id


def get_test_pttp_with_fwkeys(sqlconnection):
    set_test_pttp_ids = set(sqlconnection.session.query(PartType.pttp_id).filter(PartType.is_test_pttp == 1, PartType.pttp_id == FirmwareKey.pttp_pttp_id, FirmwareKey.key_value != None).all())
    list_test_pttp_ids = list(set_test_pttp_ids)
    count = len(list_test_pttp_ids)
    if count == 1:
        rand = 0
    else:
        rand = random.randint(0, count - 1)
    pttp_id = list_test_pttp_ids[rand][0]
    log('get_test_pttp_with_fwkeys return %s' % pttp_id)
    return pttp_id

def get_test_pttp_with_fw_keys_and_stbmodel(sqlconnection):
    test_pttp_ids = list(set(sqlconnection.session.query(PartType.pttp_id).filter(PartType.is_test_pttp == 1, PartType.pttp_id == FirmwareKey.pttp_pttp_id, FirmwareKey.key_value != None, FirmwareKey.stbm_stbm_id != None).all()))
    pttp_id = random.choice(test_pttp_ids)[0]
    log('get_test_pttp_with_fw_keys_and_stbmodel return %s' % pttp_id)
    return pttp_id


def check_pttp_keys(sqlconnection, pttp_id, file_with_keys, number_devices, pttp_kof=0):
    file = open(file_with_keys)
    first_line = file.readline().strip()
    if  first_line != 'Version 1.0':
        log('Error in first line in file with plain keys')
        return 0
    expected_devc_num = 0
    for line in file:
        expected_devc_num += 1
        items = line.split(';')[:-1]
        if items[0] != '%08x' % pttp_id:
            log('Error in format parttype in file with plain keys for device %s' % int(items[1],16))
            return 0
        if items[1] != '%016x' % expected_devc_num:
            log('Error in format device_number in file with plain keys for device %s' % int(items[1],16))
            return 0
        kl = KL.KeyLadder(sqlconnection)
        file_device_buf = ''.join(items[2:])
        buf_for_devc_from_db = ''
        if pttp_kof == 0:
            buf_for_devc_from_db = kl.get_all_plain_keys_for_device(pttp_id,expected_devc_num).encode('hex')
        elif pttp_kof == 1:
            buf_for_devc_from_db = kl.get_all_buf_for_device_after_KOF_1_obfuscation(pttp_id, expected_devc_num).encode('hex')
        elif pttp_kof == 2:
            buf_for_devc_from_db = kl.get_all_buf_for_device_after_KOF_2_obfuscation(pttp_id, expected_devc_num).encode('hex')
        if buf_for_devc_from_db != file_device_buf:
            print 'from DB  : %s' % buf_for_devc_from_db
            print 'from file: %s' % file_device_buf
            log('Error in buffer for device %s and KOF=%s' % (expected_devc_num, pttp_kof))
            return 0
        log('Checking buffer for device %s SUCCESS' % expected_devc_num)
    if expected_devc_num != number_devices:
        log('Error wrong number devices in file')
        return 0
    log('=====check_pttp_keys with KOF=%s SUCCESS=====' % pttp_kof)
    file.close()
    return 1


def check_test_pttp_keys(sqlconnection, pttp_id, testpttp_plain_keys, testpttp_obf_keys):
    full_path_to_file_with_plain_keys = os.path.join(get_homedir_out(), testpttp_plain_keys)
    full_path_to_file_with_obf_keys = os.path.join(get_homedir_out(), testpttp_obf_keys)
    pttp_kof = sqlconnection.session.query(PartType.kof_kof_id).filter(PartType.pttp_id == pttp_id).one()[0]
    number_devices = sqlconnection.session.query(Device.devc_num).filter(Device.pttp_pttp_id == pttp_id).count()
    if check_pttp_keys(sqlconnection, pttp_id, full_path_to_file_with_plain_keys, number_devices) != 1:
        log('Error in file with plain keys for test pttp')
        return 0
    if pttp_kof == 0:
        if os.path.isfile(full_path_to_file_with_obf_keys):
            log('In PTTP obfuscation is OFF but file with obfuscated keys exist')
            return 0
    else:
        if check_pttp_keys(sqlconnection,pttp_id, full_path_to_file_with_obf_keys, number_devices, pttp_kof) != 1:
            log('Error in file with obf keys for test pttp')
            return 0
    log('Checking test parttype keys SUCCESS')
    os.remove(full_path_to_file_with_plain_keys)
    if os.path.isfile(full_path_to_file_with_obf_keys):
        os.remove(full_path_to_file_with_obf_keys)
    return 1


def get_devices_status_from_test_pttp(sqlconnection, pttp_id):
    pttp_ids = sqlconnection.session.query(Device.dvst_dvst_id).filter(Device.pttp_pttp_id == pttp_id).all()
    set_pttp_ids = set(pttp_ids)
    if len(set_pttp_ids) != 1:
        log('Error in device statuses for part_type %s ' % pttp_id)
        return 0
    return list(set_pttp_ids)[0][0]


def check_exported_fw_key_for_test_pttp(sqlconnection, file_with_fwkey, fwkey_id):
    fwkey_type = sqlconnection.session.query(AlgoType.altp_name).filter(AlgoType.altp_id == FirmwareKey.altp_altp_id, FirmwareKey.fwky_id == fwkey_id).one()[0]
    dvcl_pttp_stb_ids = sqlconnection.session.query(FirmwareKey.dvcl_dvcl_id, FirmwareKey.pttp_pttp_id, FirmwareKey.stbm_stbm_id).filter(FirmwareKey.fwky_id == fwkey_id).one()
    kl = KL.KeyLadder(sqlconnection)
    full_path_to_file_with_fw_keys = os.path.join(get_homedir_out(), file_with_fwkey)
    plain_fw = kl.get_plain_fw_key(dvcl_pttp_stb_ids[0], fwkey_id, dvcl_pttp_stb_ids[1], dvcl_pttp_stb_ids[2])
    file = open(full_path_to_file_with_fw_keys)
    if fwkey_type == 'aes':
        if file.readline().strip() != 'Version 1.0':
            log('Error in first line in file')
            return 0
        items = file.readline().strip().split('=')
        dict_key = {items[0].strip() : items[1].strip()}
        if dict_key['Key_value'] != plain_fw.encode('hex'):
            log('Error in plain value of fw aes key in file')
            return 0
    elif fwkey_type == 'rsa':
        rsa_obj = RSA.importKey(plain_fw)
        pem_from_db = rsa_obj.exportKey('PEM', pkcs=8)
        rsa_from_file = file.read()
        if rsa_from_file.strip() != pem_from_db.strip():
            log('Error in plain value of  rsa fw key in file')
            return 0
    log('Checking FW key with id %s SUCCESS' % fwkey_id)
    file.close()
    return 1