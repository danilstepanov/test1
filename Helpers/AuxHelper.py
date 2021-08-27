import struct
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
# from Logger import Logger
from KeyLadder import KeyLadder
from Helpers.KmiHelper import get_homedir_out
from Management import *


from Crypto.Signature import PKCS1_v1_5



class AuxKeys:
    le_keys = 1
    ck_ip_keys = 2
    pairing_keys = 3
    sp_security_contants = 4


class AuxKeyLength:
    le = 16
    ck = 32


class AuxHelper(object):

    def __init__(self, sqlalchemy):
        self.db = sqlalchemy
        self.key_ladder = KeyLadder(self.db)
        self.logger = Logger()
        self.version = 0
        self.dict_plain_le_set = {}

    def check_aux_keyset(self, pttp_id, aux_keyset_id, le_keyset_name, key_type=AuxKeys.le_keys):
        try:
            db_aux_key_set = self.db.session.query(LEKeySet).filter(LEKeySet.lest_id == aux_keyset_id, LEKeySet.lest_name == le_keyset_name, LEKeySet.pttp_pttp_id == pttp_id, LEKeySet.aktp_aktp_id == key_type).one()
            self.logger.info('check_aux_keyset for aux_keyset_id %s return 1' % aux_keyset_id)
            return 1
        except sqlalchemy.orm.exc.NoResultFound as x:
            self.logger.error(x, x.args)
            return 0
        except sqlalchemy.orm.exc.MultipleResultsFound as x:
            self.logger.error(x, x.args)
            return 0

    def get_number_keys_in_aux_keyset(self, keyset_id):
        return self.db.session.query(LEKey).filter(LEKey.lest_lest_id == keyset_id).count()

    def get_number_rows(self, table_name=None):
        if table_name == 'kmi_le_export_history':
            return self.db.session.query(LEExportHistory).count()
        elif table_name == 'kmi_le_keys':
            return self.db.session.query(LEKey).count()
        else:
            return self.db.session.query(LEKeySet).filter(LEKeySet.del_date == None).count()

    def check_format_of_auxkeys(self, keyset_id):
        tuple_aux_keys = self.db.session.query(LEKey.key_value, LEKey.key_length, LEKeySet.aktp_aktp_id).filter(LEKeySet.lest_id == LEKey.lest_lest_id,  LEKey.lest_lest_id == keyset_id).all()
        pttp_id = self.db.session.query(LEKeySet.pttp_pttp_id).filter(LEKeySet.lest_id == keyset_id).one()[0]
        i = 0
        for tuple_aux_key in tuple_aux_keys:
            type = tuple_aux_key[2]
            key = tuple_aux_key[0]
            size = tuple_aux_key[1]
            if type == AuxKeys.le_keys:
                assert(size == AuxKeyLength.le), 'Wrong size of LE keys'
            elif type == AuxKeys.ck_ip_keys:
                assert(size == AuxKeyLength.ck), 'Wrong size of CK keys'
            if self.key_ladder.check_signed_encrypted_buffer(key, pttp_id, aes_mode='CBC', expected_key_len=size) == 0:
                self.logger.error('check_format_of_auxkeys UNSUCCESS for key %s in keyset %s' % (i, keyset_id))
                i += 1
                return 0
        self.logger.info('check_format_of_auxkeys SUCCESS for le_keysetid = %s ' % keyset_id)
        return 1

    def check_aux_keyset_list(self, pttp_id, kmi_auxset_list):
        pttp_name = self.db.session.query(PartType.pttp_name).filter(PartType.pttp_id == pttp_id).one()[0]
        db_auxset_list = self.db.session.query(LEKeySet.lest_id, LEKeySet.lest_name, LEKeySet.aktp_aktp_id).filter(LEKeySet.pttp_pttp_id == pttp_id).all()
        if len(db_auxset_list) != len(kmi_auxset_list):
            self.logger.error('Wrong size of lekeyset_list: in DB %s , in KMI %s' % (len(db_auxset_list), len(kmi_auxset_list)))
            return 0
        if len(kmi_auxset_list) == 0:
            return 'auxkeysetlist is empty'
        for item1 in db_auxset_list:
            i = 0
            db_aux_type = item1.aktp_aktp_id
            db_aux_name = self.db.session.query(AuxKeyType.aktp_name).filter(AuxKeyType.aktp_id == db_aux_type).one()[0]
            for item2 in kmi_auxset_list:
                i += 1
                if item1.lest_id == item2.auxSetId and item1.lest_name == item2.auxSetName and pttp_name == item2.partTypeName and pttp_id == item2.partTypeId and db_aux_type == item2.keyType and db_aux_name == item2.keyTypeName :
                    break
                if i == len(kmi_auxset_list):
                    self.logger.error('In KMI list there are NO auxKeySetId %s' % item1.lest_id)
                    return 0
        self.logger.info('Checking auxKeySetList for part_type %s SUCCESS' % pttp_id)
        return 1

    def calc_version_by_leset_id_and_pttps(self,le_set_id, pttp_id1, pttp_id2):
        versions = set(self.db.session.query(LEExportHistory.lexh_version).filter(LEExportHistory.lest_lest_id == le_set_id, LEExportHistory.pttp_pttp_id1 == pttp_id1, LEExportHistory.pttp_pttp_id2 == pttp_id2).all())
        if len(versions) == 1:
            return versions.pop()[0]
        elif len(versions) > 1:
            self.logger.error('There are more than one version in DB for le_set_id %s, part_type_id1 %s, part_type_id2' % (le_set_id, pttp_id1, pttp_id2))
            return -1
        versions = self.db.session.query(LEExportHistory.lexh_version).filter(LEExportHistory.pttp_pttp_id1 == pttp_id1, LEExportHistory.pttp_pttp_id2 == pttp_id2).order_by(LEExportHistory.lexh_version.desc()).all()
        if len(versions) == 0:
            return 1
        else:
            return versions[0][0] + 1

    def get_version_from_db(self, le_set_id, pttp_id1, pttp_id2):
        versions = set(self.db.session.query(LEExportHistory.lexh_version).filter(LEExportHistory.lest_lest_id == le_set_id, LEExportHistory.pttp_pttp_id1 == pttp_id1, LEExportHistory.pttp_pttp_id2 == pttp_id2).all())
        if len(versions) == 1:
            return versions.pop()[0]
        elif len(versions) > 1:
            self.logger.error('There are more than one version in DB for le_set_id %s, part_type_id1 %s, part_type_id2' % (le_set_id, pttp_id1, pttp_id2))
            return -1
        elif len(versions) == 0:
            self.logger.error('In DB no version fo pttp1 %s, pttp2 %s, leset_id %s' % (pttp_id1, pttp_id2, le_set_id))
            return 0

    def get_plain_le_key_from_db_buf(self, le_key_buf, pttp_id):
        return self.key_ladder.decrypt_buf_by_kmi_ladder(le_key_buf, pttp_id)

    def get_plain_le_keys_for_leset_id(self, le_set_id, order_by_asc=False):
        plain_leset = self.dict_plain_le_set.get(le_set_id, '')
        if plain_leset == '':
            pttp_id = self.db.session.query(LEKeySet.pttp_pttp_id).filter(LEKeySet.lest_id == le_set_id).one()[0]
            if order_by_asc is not True:
                le_keys_from_db = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == le_set_id).all()
            else:
                le_keys_from_db = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == le_set_id).order_by(LEKey.key_index.asc()).all()
            for item in le_keys_from_db:
                le_key_buf = item[0]
                plain_le_key = self.get_plain_le_key_from_db_buf(le_key_buf, pttp_id)
                plain_leset += plain_le_key
        self.dict_plain_le_set[le_set_id] = plain_leset
        return plain_leset

    def get_exported_filename(self, le_set_id, pttp_id1, otp_key_id1, pttp_id2, otp_key_id2):
        self.version = self.calc_version_by_leset_id_and_pttps(le_set_id, pttp_id1, pttp_id2)
        data_type = 1
        self.logger.info('pttp_id1 =  %s, pttp_id2 = %s' %(pttp_id1, pttp_id2))
        filename = '%02x_%02x_%08x_%s_%08x_%s_lekeys.dat' % (data_type, self.version, pttp_id1, otp_key_id1, pttp_id2, otp_key_id2)
        self.logger.info('Expected filename : %s ' % filename)
        return filename

    def check_LE_file_format(self, LE_data, pttp_id1, pttp_id2):
        offset = 0
        if LE_data[offset] != '\x01':
            self.logger.error('Wrong Type in LE file')
            return 0
        offset += 1
        if struct.unpack("<B", LE_data[offset])[0] != self.version:
            self.logger.error('Wrong version in LE file')
            return 0
        offset += 1
        if struct.unpack("<H", LE_data[offset:offset+2])[0] != pttp_id1 or struct.unpack("<H", LE_data[offset+2:offset+4])[0] != pttp_id2 or struct.unpack("<H", LE_data[offset+4:offset+6])[0] != 0:
            self.logger.error('Wrong Type attributes in LE file')
            return 0
        offset += 6
        payload_length = struct.unpack("<H", LE_data[offset:offset+2])[0]
        if payload_length != 592:
            self.logger.error('Wong size of payload in LE file')
            return 0
        if (offset + 594) != len(LE_data):
            self.logger.error('Wrong size of payload data in LE fiel')
            return 0
        self.logger.info('checking LE file format is SUCCESS')
        return 1

    def check_hash(self, data):
        hash_data = data[-32:]
        data_for_hash = data[:-32]
        calc_hash = SHA256.new(data_for_hash)
        if hash_data != calc_hash.digest():
            return 0
        return 1

    def get_enc_le_set_keys(self, le_set_id, pttp_id, otp_key_id):
        com_key = self.key_ladder.get_plain_otp_key(pttp_id, otp_key_id)
        if len(com_key) > 16:
            self.logger.info('OTP key with index %s has length %s, take first 16 bytes' % (otp_key_id,len(com_key)))
            com_key = com_key[:16]
        cipher = AES.new(com_key, AES.MODE_ECB)
        plain_le_set = self.get_plain_le_keys_for_leset_id(le_set_id)
        le_set_enc = cipher.encrypt(plain_le_set)
        if len(le_set_enc) != 256:
            self.logger.error('Wrong summary size of le_keys from DB')
            return 0
        return le_set_enc

    def check_le_keys(self, le_set_id, pttp_id, otp_key_id, encrypted_le_keys):
        if len(encrypted_le_keys) != 256:
            self.logger.error('Wrong size of le_keys, size = %s' % len(encrypted_le_keys))
            return 0
        enc_le_set_keys = self.get_enc_le_set_keys(le_set_id, pttp_id, otp_key_id)
        self.logger.info('Encrypted LE key block from DB: %s' % encrypted_le_keys.encode('hex'))
        self.logger.info('Encrypted LE key block:         %s' % enc_le_set_keys.encode('hex'))
        if enc_le_set_keys != encrypted_le_keys:
            return 0
        return 1

    def check_le_block(self, le_set_id, pttp_id, otp_key_id, le_key_block):
        if self.check_hash(le_key_block) == 0:
            self.logger.error('Wrong HASH in le_block')
            return 0
        self.logger.info('Checking HASH in le_block is SUCCESS')
        offset = 0
        if (struct.unpack('<L', le_key_block[offset:offset+4]))[0] != pttp_id:
            self.logger.error('Wrong part_type_id in le_block')
            return 0
        self.logger.info('Checking part_type_id in le_block is SUCCESS')
        offset += 4
        if struct.unpack('<H', le_key_block[offset:offset+2])[0] != otp_key_id:
            self.logger.error('Wrong otp_key_id in le_block')
            return 0
        self.logger.info('Checking otp_key_id in le_block is SUCCESS')
        offset += 2
        if struct.unpack('<H', le_key_block[offset:offset+2])[0] != self.version:
            self.logger.error('Wrong version in le_block')
            return 0
        self.logger.info('Checking version in le_block is SUCCESS')
        offset += 2
        encrypted_le_keys = le_key_block[offset:-32]
        if self.check_le_keys(le_set_id, pttp_id, otp_key_id, encrypted_le_keys) == 0:
            self.logger.error('Wrong encrypted le_keys')
            return 0
        self.logger.info('Checking encrypted le_keys in le_block is SUCCESS')

    def check_file_with_exported_LE(self, kmi_path_to_le_file, le_set_id, pttp_id1, otp_key_id1, pttp_id2, otp_key_id2):
        expected_exported_file_name = self.get_exported_filename(le_set_id, pttp_id1, otp_key_id1, pttp_id2, otp_key_id2)
        self.logger.info('Expected_exported_filename = %s' % expected_exported_file_name)
        self.logger.info('Filename from KMI          = %s' % kmi_path_to_le_file)
        path_to_file = os.path.join(get_homedir_out(), expected_exported_file_name)
        if path_to_file != kmi_path_to_le_file:
            self.logger.error('Expected path_to_le_file -  %s, from kmi - %s ' % (path_to_file, kmi_path_to_le_file))
            return 0
        try:
            LE_date = open(path_to_file).read()
        except Exception:
            self.logger.error('There are no file with name %s ' % path_to_file)
            return 0
        self.logger.info('Checking name file with LE_blocks is SUCCESS')
        if self.check_LE_file_format(LE_date, pttp_id1, pttp_id2) == 0:
            self.logger.error('Checking LE file format is NOT SUCCESS')
            return 0
        self.logger.info('Checking file with exported LE_blocks is SUCCESS')
        LE_key_block1 = LE_date[10:306]
        LE_key_block2 = LE_date[306:]
        self.logger.info('=====Checking LE_block1=====')
        if self.check_le_block(le_set_id, pttp_id1, otp_key_id1, LE_key_block1) == 0:
            self.logger.error('checking LE_key_block1 is NOT SUCCESS')
            return 0
        self.logger.info('Checking LE_block1 is SUCCESS')
        self.logger.info('=====Checking LE_block2=====')
        if self.check_le_block(le_set_id, pttp_id2, otp_key_id2, LE_key_block2) == 0:
            self.logger.error('checking LE_key_block2 is NOT SUCCESS')
            return 0
        self.logger.info('Checking LE_block2 is SUCCESS')
        self.logger.info('=====LEExport SUCCESS=====')
        return 1

    def is_auxset_deleted(self, auxset_id):
        try:
            self.db.session.query(LEKeySet).filter(LEKeySet.lest_id == auxset_id, LEKeySet.del_date != None).one()
            self.logger.info('is_auxset_deleted for auxset_id =  %s return 1' % auxset_id)
            return 1
        except sqlalchemy.orm.exc.NoResultFound as x:
            self.logger.error(x, x.args)
            return 0
        except sqlalchemy.orm.exc.MultipleResultsFound as x:
            self.logger.error(x, x.args)
            return 0

    def clear_export_history(self):
        try:
            self.db.session.query(LEExportHistory).delete()
            self.db.session.commit()
        except Exception as e:
            self.logger.info('ERROR in deleting table %s, rollbacking' % 'kmi_partners')
            self.db.session.rollback()

    def get_any_auxkeyset_id(self, aux_key_type, pttp_id, linked=1):
        if pttp_id:
            if linked == 1:
                auxset_ids = self.db.session.query(LEKeySet.lest_id).filter(LEKeySet.aktp_aktp_id == aux_key_type, LEKeySet.pttp_pttp_id == pttp_id).all()
            else:
                auxset_ids = self.db.session.query(LEKeySet.lest_id).filter(LEKeySet.aktp_aktp_id == aux_key_type, LEKeySet.pttp_pttp_id != pttp_id).all()
        else:
            auxset_ids = self.db.session.query(LEKeySet.lest_id).filter(LEKeySet.aktp_aktp_id == aux_key_type).all()
        try:
            auxset_id = random.choice(auxset_ids)[0]
        except Exception as E:
            self.logger.info('%s, Adding aux_keyset' % E)
            auxset_id = kmi_add_aux_keyset(pttp_id, 'First_aux_keyset', aux_key_type)
        self.logger.info('get_any_auxkeyset_id return %s with type %s' % (auxset_id, aux_key_type))
        return auxset_id

    def check_exported_ck_keyset(self, ckset_id, out_path):
        path_to_files = os.path.join(get_homedir_out(), out_path)
        ckset_info = self.db.session.query(LEKeySet.lest_name, LEKeySet.pttp_pttp_id).filter(LEKeySet.lest_id == ckset_id).one()
        ckset_name = ckset_info[0]
        pttp_id = ckset_info[1]
        exported_files = [name for name in os.listdir(path_to_files)]
        assert(len(exported_files) == 4), 'ERROR : wrong number exported files with CK IP keys'
        expected_files = ['%s_%s_%s_ck_ipkey.txt' % (ckset_id, ckset_name, index) for index in range(1,5)]
        assert(sorted(exported_files) == sorted(expected_files)), 'ERROR wrong number or names of exported files with ck_keys'
        for item in expected_files:
            file = open(os.path.join(path_to_files,item))
            assert(file.readline().strip() == 'Version 1.0')
            items = file.readline().strip().split('=')
            dict_key = {items[0].strip() : items[1].strip()}
            ck_index = int(item.split('_')[-3])
            ck_db_buf = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == ckset_id, LEKey.key_index == ck_index).one()[0]
            plain_ck = self.key_ladder.decrypt_buf_by_kmi_ladder(ck_db_buf, pttp_id)
            assert(dict_key['Key_value'] == plain_ck.encode('hex')), 'ERROR: wrong value of plain CK key with index %s, plain ck from db = %s' % (ck_index, plain_ck.encode('hex'))
        self.logger.info('=====Checking exported CK IP Keys SUCCESS=====')

    def check_generated_pairing_keys(self, pttp_id, list_devices_with_version, versions):
        versions = map(int, versions)
        self.logger.info('List versions: %s' % versions)
        self.logger.info('List devices with versions: %s' % list_devices_with_version)
        start_device = list_devices_with_version[0][0]
        end_device = list_devices_with_version[0][1]
        for device in range(start_device, end_device+1):
            version_before_export = list_devices_with_version[1][device].keys()
            if len(version_before_export) == 0:
                version_before_export = [0]
            version_after_export = []
            version_after_export.extend(version_before_export)
            for version in versions:
                if version == 0:
                    next_ver = max(version_after_export)+1
                    version_after_export.append(next_ver)
                    self.logger.info('Version = 0, should be incremenent version, next_ver = %s for device = %s' % (next_ver, device))
                    db_pairing_key = self.db.session.query(AuxKey.devc_num, AuxKey.length, AuxKey.value).filter(AuxKey.devc_num == device, AuxKey.pttp_pttp_id == pttp_id, AuxKey.version == next_ver).one()
                else:
                    db_pairing_key = self.db.session.query(AuxKey.devc_num, AuxKey.length, AuxKey.value).filter(AuxKey.devc_num == device, AuxKey.pttp_pttp_id == pttp_id, AuxKey.version == version).one()
                    self.logger.info('db_pairing_key for device %s and version %s : %s ' % (device, version, db_pairing_key[2].encode('hex')))
                    if version in  version_before_export:
                        self.logger.info('WARNING:version %s for device %s already exist in DB, start check that it will not regenerated' % (version, device))
                        before_exp_pairing_key = list_devices_with_version[1][device][version]
                        assert(db_pairing_key[2] == before_exp_pairing_key), 'Wrong pairing key for existing version, possible it regenerated'
                        self.logger.info('WARNING:version %s for device %s already exist in DB and NOT regenerated' % (version, device))
                    else:
                        version_after_export.append(version)
                assert(self.key_ladder.check_signed_encrypted_buffer(db_pairing_key[2], device, aes_mode='CBC', expected_key_len=db_pairing_key[1]) != 0), 'Wrong format of pairing key for device %s and version %s' % (db_pairing_key[0], version)
                self.logger.info('Check generated pairing key for device %s and version %s SUCCESS' % (device, version))
            if version_after_export.count(0) != 0:
                version_after_export.remove(0)
            db_versions = self.db.session.query(AuxKey.version).filter(AuxKey.devc_num == device, AuxKey.pttp_pttp_id == pttp_id).all()
            list_db_versions = [item[0] for item in db_versions]
            assert(sorted(list_db_versions) == sorted(version_after_export)), 'Wrong list versions in DB after generated pairing keys for deive %s' % device
            self.logger.info('Check generated pairing key for device %s SUCCESS' % device)
        self.logger.info('check_generated_pairing_keys for part_type = %s SUCCESS' % pttp_id)

    def check_exported_pairing_keys(self,  pttp_id, start_devc, end_devc, list_versions, otp_key_index, auxset_id, aux_key_index, algo,  keys_file):
        list_versions = map(int, list_versions)
        if algo.lower() == 'aes-128-ecb':
            algo = 'ECB'
        full_path_to_keys = os.path.join(get_homedir_out(), keys_file)
        pttp_id_ckip = self.db.session.query(LEKeySet.pttp_pttp_id).filter(LEKeySet.lest_id == auxset_id).one()[0]
        ck_ip_key_buf = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == auxset_id, LEKey.key_index == aux_key_index).one()[0]
        ck_ip_key_value = self.key_ladder.decrypt_buf_by_kmi_ladder(ck_ip_key_buf, pttp_id_ckip)[:16]
        logger.info('plain ck_ip_key: %s' % ck_ip_key_value.encode('hex'))
        with open(full_path_to_keys) as file:
            processed_lines = 0
            first_line = file.readline().rstrip()
            assert(first_line == 'Version 1.0'), 'Wrong version in config file for APS'
            for cur_device in range(start_devc, end_devc+1):
                dev_st = self.db.session.query(Device.dvst_dvst_id).filter(Device.devc_num == cur_device, Device.pttp_pttp_id == pttp_id).one()[0]
                assert(dev_st != 1), 'Wrong device status, must be not equal 1'
                line = file.readline()
                while line == '\n':
                    line = file.readline()
                assert(line != ''), 'All file processed, but for device %s NO keys in file' % cur_device
                processed_lines += 1
                items = line.split(';')
                if len(items[-1].rstrip()) == 0:
                    items = items[:-1]
                assert(len(items) == (len(list_versions)*3 + 2)), 'Wrong number fileds in pairing file'
                assert(items[0] == '%08x' % cur_device), 'Wrong device in file with pairing keys for device = %s' % cur_device
                assert(items[1] == '%04x' % otp_key_index), 'Wrong otp key index in file for device = %s' % cur_device
                otp_key = self.key_ladder.get_plain_otp_key(pttp_id, otp_key_index, cur_device)[:16]
                logger.info('OTP_key with index %s and device %s is %s' % (otp_key_index, cur_device, otp_key.encode('hex')))
                encrypted_pairing_keys = items[2:]
                offset = 0
                for ver in list_versions:
                    db_pairing_buf = self.db.session.query(AuxKey.value).filter(AuxKey.devc_num == cur_device, AuxKey.pttp_pttp_id == pttp_id, AuxKey.version == ver).one()[0]
                    pairing_key = self.key_ladder.decrypt_buf_by_kmi_ladder(db_pairing_buf, cur_device)
                    logger.info('pairing_key for version = %s and device = %s :  %s' % (ver, cur_device, pairing_key.encode('hex')))
                    assert(encrypted_pairing_keys[offset] == '%04X' % ver), 'Wrong version in file for device %s' % cur_device
                    CoPro_PKValue = self.key_ladder.encrypt_buf(otp_key[:16],pairing_key, aes_mode='ECB')
                    logger.info('CoPro_PKValue for version = %s and device = %s :  %s' % (ver, cur_device, CoPro_PKValue.encode('hex')))
                    assert(encrypted_pairing_keys[offset+1] == CoPro_PKValue.encode('hex')), 'Wrong encrypted by otp_key pairing_key'
                    CAS_PKValue = self.key_ladder.encrypt_buf(ck_ip_key_value, pairing_key, aes_mode=algo)
                    logger.info('CAS_PKValue for version = %s and device = %s :  %s' % (ver, cur_device, CAS_PKValue.encode('hex')))
                    assert(encrypted_pairing_keys[offset+2] == CAS_PKValue.encode('hex')), 'Wrong encrypted by ck_ip key pairing_keys'
                    offset += 3
                    logger.info('Checking pairing keys version = %s for device %s SUCCESS' %(ver, cur_device))
                logger.info('=====Checking all encrypted pairing keys for device %s SUCCESS=====' % cur_device)
            assert(processed_lines == (end_devc - start_devc +1)), 'Wrong number lines in file with pairing keys'
            assert(file.readline() == ''), 'Not all lines from file processed'
        logger.info('=====*****check_exported_pairing_keys SUCCESS*****=====')
        return 1

    def check_exported_sps_constants(self, sps_constans_set_id, pttp_id, out_path):
        keys = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == sps_constans_set_id).order_by(LEKey.key_index).all()
        file = open(out_path)
        data = file.read(32)
        index=0
        while data:
            assert(data == self.key_ladder.decrypt_buf_by_kmi_ladder(keys[index][0], pttp_id)), 'Wrong sps_constants with index %s' % index
            index+=1
            data = file.read(32)
        assert(index -1 == 15), 'WRONG count keys in exported file'
        log('=====check_exported_sps_constants for sps_constants_set_id %s SUCCESS=====' % sps_constans_set_id)

    def check_exported_ck_ip_keys_secure(self, le_set_id, pttp, key_index, dvcl_id, fw_keys_id, filename):
        message = ''
        plain_le_set = self.get_plain_le_keys_for_leset_id(le_set_id, True)
        plain_fw_key = RSA.importKey(self.key_ladder.get_plain_fw_key(dvcl_id, fw_keys_id, pttp))
        path_to_file = get_homedir_out() + '/' + filename
        path_to_sig_file = path_to_file + '.sig'
        with open(path_to_file) as file:
            for item in file.readlines():
                message += item
            calc_hash = self.sign(message, plain_fw_key)
            assert (calc_hash.encode('hex') == open(path_to_sig_file).read()), 'Error hash is not the same'
            file.close()
        with open(path_to_file) as f:
            data = json.load(f)
            authkey = data['keyLadder']['authKey']
            pttp_id_from_file = data['keyLadder']['partTypeId']
            key_index_from_file = data['keyLadder']['rootKeyIndex']
            ckipkeys = data['ipkeys']
        assert (int(pttp_id_from_file) == int(pttp)), "Error Pttp_id in file is not correct"
        assert (int(key_index_from_file) == int(key_index)), 'Error Keyindex in file is not correct'
        plain_otp = self.key_ladder.get_plain_otp_key(pttp, key_index)
        if len(plain_otp) == 16:
            plain_authkey = self.key_ladder.decrypt_buf(plain_otp, authkey.decode('hex'))
        elif len(plain_otp) > 16:
            plain_authkey = self.key_ladder.decrypt_buf(plain_otp[:16], authkey.decode('hex'))
        else:
            return 'Error plain otp key is not equal 16 bytes'
        plain_ckipkeys = ''
        for ckipkey in ckipkeys:
            plain_ckipkey = self.key_ladder.decrypt_buf(plain_authkey, ckipkey.decode('hex'))
            plain_ckipkeys += plain_ckipkey
        assert (plain_le_set == plain_ckipkeys), 'Error plain le keys set is not the same'
        return 1

    def sign(self, message, priv_key):
        signer = PKCS1_v1_5.new(priv_key)
        digest = SHA256.new()
        digest.update(message)
        return signer.sign(digest)

    def get_any_ck_ip_keys_id(self, secure):
        if secure is None:
            return random.choice(self.db.session.query(LEKeySet.lest_id).filter(LEKeySet.aktp_aktp_id == 2).all())[0]
        else:
            return random.choice(self.db.session.query(LEKeySet.lest_id).filter(LEKeySet.aktp_aktp_id == 5).all())[0]

    def get_ptnb_by_ck_ip_keys_id(self, ck_ip_keys_id):
        pttp_id = self.db.session.query(LEKeySet.pttp_pttp_id).filter(LEKeySet.lest_id == ck_ip_keys_id).one()[0]
        dvcl_id = self.db.session.query(PartType.dvcl_dvcl_id).filter(PartType.pttp_id == pttp_id, PartType.del_date == None).one()[0]
        ptnb = self.db.session.query(PartNumber.ptnm_id).filter(PartNumber.pttp_pttp_id == pttp_id, PartNumber.del_date == None, PartNumber.dvcl_dvcl_id == dvcl_id).one()[0]

    def get_aux_key_types_by_id(self, id):
        return self.db.session.query(LEKeySet.aktp_aktp_id).filter(LEKeySet.lest_id == id).one()[0]

    def check_cloned(self, le_set_id, max_lest_id):
        le_set_id_cloned = max_lest_id + 1
        plain_le_set = self.get_plain_le_keys_for_leset_id(le_set_id, True)
        plain_le_set_cloned = self.get_plain_le_keys_for_leset_id(le_set_id_cloned, True)
        assert (plain_le_set == plain_le_set_cloned), 'Error, cloned key set is not the same'
        return 1

    def get_max_lest_id(self):
        return self.db.session.query(func.max(LEKeySet.lest_id)).scalar()


if __name__== '__main__':
    le = AuxHelper()
    print le.check_file_with_exported_LE(1,1,3, 111,4)
