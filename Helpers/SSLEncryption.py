import struct
import zipfile
import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Helpers.KeyLadder import KeyLadder
from DB_ORM_classes import *
from Database import *
import Management as mng
from Logger import log
from KmiHelper import *
from OpenSSL import crypto

SSL_TYPE = {'Gameconsole':16, 'Pandora':21, 'Selene':22, 'APlatform':23}


class SSLEncryption(object):

    def __init__(self, sql_obj):
        self.db = sql_obj
        self.kl = KeyLadder(self.db)
        self.input_dict_with_cert = None

    def get_output_dict_with_cert_from_binfile(self, file, input_dict_with_cert):
        first_dev_id = int(file.split('_')[-4])
        last_dev_id = int(file.split('_')[-3])
        blocks_count_from_filename = int(file.split('_')[-2])
        cert_data = open(file).read()
        blocks_count = struct.unpack("<L",cert_data[0:4])[0]
        if blocks_count != blocks_count_from_filename:
            log('ERROR: must be %s certificates, but in file %s certificates' % (blocks_count_from_filename, blocks_count))
            return None
        offset = 4
        cert_dict = {}
        list_int_keys = [int(key[:-4]) for key in (input_dict_with_cert.keys())]
        while offset < len(cert_data):
            if(first_dev_id in list_int_keys):
                payload_len = struct.unpack("<H", cert_data[offset:offset+2])[0]
                offset+=2
                payload = cert_data[offset:offset+payload_len]
                #print 'Parsing the block for number %s :' %first_dev_id
                dict_for_one_device = self.get_dict_with_perscert_and_perskey_from_data(payload, payload_len)
                cert_dict['%010d'%first_dev_id] = dict_for_one_device
                offset+=payload_len
            first_dev_id+=1
        if offset != len(cert_data) or len(cert_dict) != blocks_count:
            log('ERROR: wrong format of file with certificates or wrong block_counts')
            return None
        return cert_dict

    def get_dict_with_perscert_and_perskey_from_data(self, data, data_len):
        dict_with_certificate_and_key = {}
        if len(data) != data_len:
            log('ERROR: wrong input data')
            return None
        offset = 0
        if data[offset] != '\x10':
            log('wrong payload format, id of certificates block payload must be 0x10')
            return None
        offset+=1
        cert_block_len = struct.unpack("<H", data[offset:offset+2])[0]
        offset+=2
        if data[offset] != '\x11':
            log('wrong payload format, id of Personal Certificates Value must be 0x11')
            return None
        offset+=1
        pers_cert_len = struct.unpack("<H", data[offset:offset+2])[0]
        dict_with_certificate_and_key['pers_certificates_length'] = pers_cert_len
        offset+=2
        dict_with_certificate_and_key['PersonalCertificate'] = data[offset:offset+pers_cert_len]
        offset+=pers_cert_len
        if data[offset] != '\x12':
            log('wrong payload format, id of Personal Key Value must be 0x12')
            return None
        offset+=1
        pers_key_len = struct.unpack("<H", data[offset:offset+2])[0]
        dict_with_certificate_and_key['pers_key_length'] = pers_key_len
        offset+=2
        dict_with_certificate_and_key['PersonalKey'] = data[offset:offset+pers_key_len]
        offset+=pers_key_len
        if offset != data_len:
            log('ERROR:wrong_data: offset != data_len')
            return None
        return dict_with_certificate_and_key

    def check_encrypt_ssl_certificates_gameconsole(self, pttp_id, dvkm_common_key_id, manufacturer, input_zip_with_cert, certs_per_file, full_output_filename_fromDal):
        log('=====check_encrypt_ssl_certificates_gameconsole START=====')
        dev_cl_id = self.db.session.query(PartType.dvcl_dvcl_id).filter(PartType.pttp_id == pttp_id).one()
        common_key_id = self.db.session.query(DeviceKeymap.key_index).filter(DeviceKeymap.dvcl_dvcl_id == dev_cl_id, DeviceKeymap.dvkm_id == dvkm_common_key_id).one()[0]
        full_input_zip = os.path.join(get_homedir_in(), input_zip_with_cert)
        input_dict_with_cert = get_dict_with_cert_from_zip(full_input_zip)
        output_zip = full_output_filename_fromDal.split('/')[-1]
        path_for_dat_file = 'output_certificates'
        list_output_filenames = self.extract_zip(full_output_filename_fromDal, path_for_dat_file)
        input_keys = input_dict_with_cert.keys()
        input_keys.sort()
        all_amount_input_cert = len(input_dict_with_cert)
        log('===Checking name of output zip archive with certificates:===')
        expected_output_filename = '%s_%08X_%s_%s_%s_%s_certificates.zip' % (manufacturer, pttp_id, common_key_id, int(input_keys[0][:-4]), int(input_keys[-1][:-4]), all_amount_input_cert)
        log('expected name of output file with certificates : %s'  % expected_output_filename)
        assert(expected_output_filename == full_output_filename_fromDal.split('/')[-1]), 'ERROR:wrong name of output file with certificates, name from DAL = %s' % output_zip

        log('===Checking amount output files:===')
        if certs_per_file == 0 or certs_per_file >= all_amount_input_cert:
            expect_nmb_output_files = 1
        else:
            expect_nmb_output_files = all_amount_input_cert/certs_per_file if(all_amount_input_cert % certs_per_file == 0) else all_amount_input_cert/certs_per_file + 1
        log('expected amount output files = %s' % expect_nmb_output_files)
        log('amount output files in output zip archive with certificates = %s' %len(list_output_filenames))
        assert(expect_nmb_output_files == len(list_output_filenames)), 'ERROR:wrong number output files in archive with certificates'

        log('===Checking names of output files with certificates in archive===')
        list_expected_output_filenames = []
        if expect_nmb_output_files != 1:
            for i in range(expect_nmb_output_files):
                if i != (expect_nmb_output_files-1):
                    list_expected_output_filenames.append('%s_%08X_%s_%s_%s_%s_certificates.dat' %(manufacturer, pttp_id, common_key_id, int(input_keys[certs_per_file*i][:-4]), int(input_keys[certs_per_file*i + certs_per_file-1][:-4]), certs_per_file))
                else:
                    list_expected_output_filenames.append('%s_%08X_%s_%s_%s_%s_certificates.dat' %(manufacturer, pttp_id, common_key_id, int(input_keys[certs_per_file*i][:-4]), int(input_keys[-1][:-4]), all_amount_input_cert - certs_per_file*i))
        else:
            list_expected_output_filenames.append('%s_%08X_%s_%s_%s_%s_certificates.dat' % (manufacturer, pttp_id, common_key_id, int(input_keys[0][:-4]), int(input_keys[-1][:-4]), all_amount_input_cert))
        log('expected list of output filenames is : %s' %list_expected_output_filenames)
        log('list output filenames from input zip archive is : %s' %list_output_filenames)
        diff_two_list = [e for e in list_expected_output_filenames if not e in list_output_filenames]
        if len(diff_two_list) !=0 or len(list_expected_output_filenames) != len(list_output_filenames):
            log('ERROR:wrong output filenames from output zip archive')
            log('there are %s in list_expected_output_filenames but no in list_output_filenames' % diff_two_list)
            return 0
        else:
            log('===Checking names of output files with certificates in archive is OK === ')

        #self.logger.info('===Checking encryption of personal key===')
        common_key_data = self.kl.get_plain_otp_key(pttp_id, common_key_id)
        iv_data = self.getIV_by_pttp_gameconsole(pttp_id)
        list_file_with_error = []
        for name in list_output_filenames:
            if self.check_dat_file(path_for_dat_file, name, common_key_data, iv_data, input_dict_with_cert) != 1:
                log('ERROR: The data in file %s is wrong' % name)
                list_file_with_error.append(name)
        if len(list_file_with_error) != 0:
            log('ERROR: encryption wrong in files %s ' % list_file_with_error)
            return 0
        log('===All checking is OK===')
        return 1

    def check_encrypt_ssl_certificates_stingray(self, input_zip_file, full_path_output_file):
        result = self.db.conn.execute('select value_binary, rprm_id from kmi_resource_params where rprm_code=\'SSL_STINGRAY_KEY\'').fetchone()
        stingray_key_buf = result['value_binary']
        rprm_id = result['rprm_id']
        stingray_key = self.kl.decrypt_buf_by_kmi_ladder(stingray_key_buf, rprm_id)
        log('=====check_encrypt_ssl_certificates_stingray====')
        expected_output_file = input_zip_file.replace('cert', 'PersonalKeys')
        assert(expected_output_file == full_path_output_file.split('/')[-1]), 'Wrong output_filename'
        input_dict_with_certs = get_dict_with_cert_from_zip('%s/%s' % (get_homedir_in(), input_zip_file))
        output_dict_with_certs = get_dict_with_cert_from_zip(full_path_output_file)
        assert(len(input_dict_with_certs) == len(output_dict_with_certs)), 'Wrong number certificates in archives'
        for key in sorted(input_dict_with_certs.keys()):
            assert(len(input_dict_with_certs[key]) == len(output_dict_with_certs[key])), 'Wrong number files for one device_id'
            input_certificate = input_dict_with_certs[key]['PersonalCertificate']
            input_pers_key = input_dict_with_certs[key]['PersonalKey']
            assert(input_certificate == output_dict_with_certs[key]['PersonalCertificate'])
            try:
                sn = crypto.load_certificate(crypto.FILETYPE_PEM, input_certificate).get_serial_number()
            except:
                sn = crypto.load_certificate(crypto.FILETYPE_ASN1, input_certificate).get_serial_number()
            iv = ('%032x' % sn).decode('hex')
            encrypted_input_pers_key = self.encryptPersonalKey(input_pers_key, stingray_key, iv)
            hex_ecnrypted_input_pers_key = encrypted_input_pers_key.encode('hex')
            hex_pers_key_from_dall = output_dict_with_certs[key]['PersonalKey'].encode('hex')
            assert(encrypted_input_pers_key == output_dict_with_certs[key]['PersonalKey'][16:]), 'Wrong encrypted Personal Key'
            if len(input_dict_with_certs[key]) > 2:
                assert(input_dict_with_certs[key]['PersonalCertificate.sha256'] == output_dict_with_certs[key]['PersonalCertificate.sha256']), 'WRONG hash for certificate'
                assert(input_dict_with_certs[key]['PersonalKey.sha256'] == output_dict_with_certs[key]['PersonalKey.sha256']), 'WRONG hash for personal key'
        log('===check_encrypt_ssl_certificates_stingray SUCCESS===')
        return 1

    def check_encrypt_ssl_certificates_universal(self, pttp_id, dvkm_common_key_id, aux_set_id, iv_type, ladder_lvl, ssl_type, full_path_input_file, full_path_output_file):
        log('=====check_encrypt_ssl_certificates_universal====')
        dev_cl_id = self.db.session.query(PartType.dvcl_dvcl_id).filter(PartType.pttp_id == pttp_id).one()
        common_key_id = self.db.session.query(DeviceKeymap.key_index).filter(DeviceKeymap.dvcl_dvcl_id == dev_cl_id,
                                                                             DeviceKeymap.dvkm_id == dvkm_common_key_id).one()[0]
        input_dict_with_certs = get_dict_with_cert_from_zip(full_path_input_file)
        output_dict_with_certs = get_dict_with_cert_from_zip(full_path_output_file)
        assert (len(input_dict_with_certs) == len(output_dict_with_certs)), 'Wrong number certificates in archives'
        for item in sorted(input_dict_with_certs.keys()):
            assert(len(input_dict_with_certs[item]) == len(output_dict_with_certs[item])), 'Wrong number files for one device_id'
            input_certificate = input_dict_with_certs[item]['PersonalCertificate']
            input_pers_key = input_dict_with_certs[item]['PersonalKey']
            output_pers_key = output_dict_with_certs[item]['%02x.12' % ssl_type]
            assert (input_certificate == output_dict_with_certs[item]['%02x.11' % ssl_type])
            if iv_type == 'serial':
                try:
                    sn = crypto.load_certificate(crypto.FILETYPE_PEM, input_certificate).get_serial_number()
                except:
                    sn = crypto.load_certificate(crypto.FILETYPE_ASN1, input_certificate).get_serial_number()
                iv = ('%032x' % sn).decode('hex')
            elif iv_type == 'random':
                iv = output_pers_key[:16]
                iv_hex = iv.encode('hex')
            key = self.get_key_by_ladder_lvl(pttp_id, common_key_id, aux_set_id,ladder_lvl)
            encrypted_input_pers_key = self.encryptPersonalKey(input_pers_key, key, iv)
            hex_key = key.encode('hex')
            hex_output_pers_key = output_pers_key[16:].encode('hex')
            hex_encrypted_pers_key = encrypted_input_pers_key.encode('hex')
            assert (encrypted_input_pers_key == output_pers_key[16:]), 'Wrong encrypted Personal Key'
            if len(input_dict_with_certs[item]) > 2:
                assert(input_dict_with_certs[item]['PersonalCertificate.sha256'] == output_dict_with_certs[item]['PersonalCertificate.sha256']), 'WRONG hash for certificate'
                assert(input_dict_with_certs[item]['PersonalKey.sha256'] == output_dict_with_certs[item]['PersonalKey.sha256']), 'WRONG hash for personal key'
        log('===check_encrypt_ssl_certificates_universal SUCCESS===')
        return 1


    def check_dat_file(self, path_for_dat_file, dat_file, common_key_data, iv_data, input_dict_with_cert):
        #self.logger.info('===Check dat file: %s === START' % dat_file)
        count_devicces_from_file_name = int(dat_file.split('_')[-2])
        first_devid = dat_file.split('_')[-4]
        last_devid = dat_file.split('_')[-3]
        ful_path_to_file = '%s/%s' %(path_for_dat_file, dat_file)
        output_dict = self.get_output_dict_with_cert_from_binfile(ful_path_to_file, input_dict_with_cert)
        assert(count_devicces_from_file_name == len(output_dict)), 'ERROR: in filename there are %s pairs certificates, in dat-file %s pairs ' % (count_devicces_from_file_name, len(output_dict))
        for key in output_dict:
            inp_key = '%s.bin' % key
            pers_key_encr = self.encryptPersonalKey(input_dict_with_cert[inp_key]['PersonalKey'], common_key_data, iv_data)
            hex_pers_key_encr = pers_key_encr.encode('hex')

            output_personal_key = output_dict[key]['PersonalKey']
            hex_output_pers_key = output_personal_key.encode('hex')
            assert (output_dict[key]['PersonalCertificate'] == input_dict_with_cert[inp_key]['PersonalCertificate']), 'WRONG output certificate'
            assert(pers_key_encr == output_personal_key), 'WRONG encrypted personal key'
        return 1

    def getIV_by_pttp_gameconsole(self, pttp_id):
        dev_cl_id = self.db.session.query(PartType.dvcl_dvcl_id).filter(PartType.pttp_id == pttp_id).one()[0]
        keymaps_len = mng.get_keymaps_length(self.db, dev_cl_id)
        comb_for_iv = struct.pack("<B",pttp_id) + struct.pack("<B",dev_cl_id) + struct.pack("<H", keymaps_len)
        return SHA256.new(comb_for_iv).digest()[:16]

    def extract_zip(self,zip, outpath = None):
        zip_file = zipfile.ZipFile(zip)
        list = zip_file.namelist()
        for name in list:
            cur_dir = os.getcwd()
            zip_file.extract(name, outpath)
        zip_file.close()
        return list

    def encryptPersonalKey(self, data, key, iv_data):
        log('len data %s' % len(data))
        len_data = 16 - (len(data) %16)
        if len_data != 16:
            log('Length data not multiple 16, adding padding!!!')
            data += chr(len_data)*len_data
        #self.logger.info('data %s: ' % data.encode('hex'))
        aes_obj = AES.new(key[:16], AES.MODE_CBC, iv_data)
        pers_key_enc = aes_obj.encrypt(data)
        #self.logger.info('Encrypted data: %s' % pers_key_enc.encode('hex'))
        #self.logger.info('Length encrypted data %s '% len(pers_key_enc))
        return pers_key_enc

    def get_key_by_ladder_lvl(self, pttp_id, common_key_index, aux_set_id, ladder_lvl):
        key = self.kl.get_plain_otp_key(pttp_id, common_key_index)
        if ladder_lvl == 'second_ladder':
            db_D1 = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == aux_set_id, LEKey.key_index==1).one()[0]
            db_D3 = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == aux_set_id, LEKey.key_index==2).one()[0]
            D1 = self.kl.decrypt_buf_by_kmi_ladder(db_D1, pttp_id)
            D3 = self.kl.decrypt_buf_by_kmi_ladder(db_D3, pttp_id)
            key = self.kl.decrypt_buf(key[:16], D1)
            hex_key = key.encode('hex')
            log(key.encode('hex'))
            key = self.kl.decrypt_buf(key[:16], D3)
            hex_key = key.encode('hex')
            log(key.encode('hex'))
        elif ladder_lvl == 'third_ladder':
            db_sc5 = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == aux_set_id, LEKey.key_index==5).one()[0]
            db_sc4 = self.db.session.query(LEKey.key_value).filter(LEKey.lest_lest_id == aux_set_id, LEKey.key_index==4).one()[0]
            sc5 = self.kl.decrypt_buf_by_kmi_ladder(db_sc5, pttp_id)
            sc4 = self.kl.decrypt_buf_by_kmi_ladder(db_sc4, pttp_id)
            sc5a = sc5[:16]
            sc4b = sc4[16:]
            sc5b = sc5[16:]
            key = self.kl.decrypt_buf(key[:16], sc5a)
            hex_key = key.encode('hex')
            key = self.kl.decrypt_buf(key[:16], sc4b)
            hex_key = key.encode('hex')
            key = self.kl.decrypt_buf(key[:16], sc5b)
            hex_key = key.encode('hex')
        return key[:16]


def get_dict_with_cert_from_zip(full_path_zip):
    file = open(full_path_zip)
    zip_file = zipfile.ZipFile(file)
    input_dict = {}
    for name in zip_file.namelist():
        output = 'input_certificates'
        zip_file.extract(name, output)
        path = '%s/%s' % (output, name)
        file2 = open(path)
        try:
            zip_file2 = zipfile.ZipFile(file2)
        except:
            log('error in %s' % name)
        dict_for_one_devid = {}
        for name2 in zip_file2.namelist():
            path_for_cert = path[:-4]
            zip_file2.extract(name2, path_for_cert)
            cert_or_key = '%s/%s' % (path_for_cert, name2)
            data_cert_or_key = open(cert_or_key).read()
            dict_for_one_devid[name2] = data_cert_or_key
        os.remove(path)
        input_dict[name] = dict_for_one_devid
    file.close()
    file2.close()
    return input_dict


def ssl_der_to_pem(full_input_zip):
    input_dict_with_cert = get_dict_with_cert_from_zip(full_input_zip)
    with zipfile.ZipFile(os.path.join(get_homedir_in(), 'certs_pem.zip'), 'w') as zip_obj2:
        for key in sorted(input_dict_with_cert.keys()):
            cert =  input_dict_with_cert[key]['PersonalCertificate']
            pers_key = input_dict_with_cert[key]['PersonalKey']
            #pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, der_cert)
            with open('PersonalCertificate', 'w') as f:
                f.write(cert)
            with open('PersonalKey', 'w') as f:
                f.write(pers_key)
            with open('PersonalCertificate.sha256', 'w') as f:
                cert_hash = SHA256.new(cert).hexdigest()
                f.write(cert_hash)
            with open('PersonalKey.sha256', 'w') as f:
                f.write(SHA256.new(pers_key).hexdigest())
            with zipfile.ZipFile(key, 'w') as zip_obj:
                zip_obj.write('PersonalCertificate')
                zip_obj.write('PersonalCertificate.sha256')
                zip_obj.write('PersonalKey')
                zip_obj.write('PersonalKey.sha256')
            zip_obj2.write(key)








