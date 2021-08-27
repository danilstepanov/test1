import hashlib

import gnupg, time, calendar, random, os

from Logger import log
from Database import Database
from DB_ORM_classes import *
from KeyLadder import *
import KmiHelper


db = Database()
kl = KeyLadder(db)


def clear_keyring(gpg_obj):
    fps = gpg_obj.list_keys(secret=True)
    for item in fps:
        gpg_obj.delete_keys(item, secret=True)
        gpg_obj.delete_keys(item)


def generate_pgp_key(email, length, key_name, type):
    is_secret=True if type == 'private' else False
    gpg = gnupg.GPG(keyring='my_keyring')
    clear_keyring(gpg)
    input_data = gpg.gen_key_input(key_type='RSA',name_email=email, key_length=length, name_real=key_name)
    key = gpg.gen_key(input_data)
    fp = key.fingerprint
    pub_key = gpg.export_keys(key, secret=is_secret)
    gpg.delete_keys(fp,True,True)
    gpg.delete_keys(fp)
    return pub_key

def generate_pgp_key_without_first_line(email, length, key_name, type):
    key = generate_pgp_key(email, length, key_name, type)
    return key[key.find('\n')+1:]


def get_any_user(sqlalchemy):
    users = sqlalchemy.session.query(User.user_id).filter(User.del_date == None).all()
    return random.choice(users)[0]



def check_public_key(sqlalchemy, user_id, key_id, key_value):
    db_key_value = sqlalchemy.session.query(UserKey.ukey_value, UserKey.user_user_id).filter(UserKey.ukey_id==key_id, UserKey.user_user_id==user_id).one()
    decrypted_db_key_value = kl.decrypt_buf_by_kmi_ladder(db_key_value[0], db_key_value[1])
    assert(decrypted_db_key_value==key_value), 'ERROR: wrong public key in DB: in DB=%s, generated=%s' % (decrypted_db_key_value, key_value)
    return 1

def get_number_keys_for_user(sqlalchemy, user_id):
    return len(sqlalchemy.session.query(UserKey).filter(UserKey.user_user_id==user_id, UserKey.del_date==None).all())

def check_pgp_key_pair(sqlalchemy, user_id, pttp_id, key_name, key_email, comment, expires_time):
    gpg = gnupg.GPG(keyring='my_keyring')
    if user_id != 0:
        key1,key2 = sqlalchemy.session.query(UserKey.ukey_id, UserKey.ukey_name, UserKey.ukey_value, UserKey.uktp_uktp_id,  UserKey.ukey_ukey_id, UserKey.ukey_email, UserKey.ukey_comment, UserKey.ukey_expires).filter(UserKey.user_user_id==user_id).order_by(UserKey.ukey_id.desc()).limit(2).all()
        assert (key1[1] == key2[1] and key1[1] == key_name), 'Wrong key_name for user=%s and pttp=%s' % (user_id, pttp_id)
        assert (key1[5] == key2[5] and key1[5] == key_email), 'Wrong key_email for user=%s and pttp=%s' % (user_id, pttp_id)
        assert (key1[6] == key2[6] and key1[6] == comment), 'Wrong comment for user=%s and pttp=%s' % (user_id, pttp_id)
        if key1[3] == 1:
            assert (key2[3] == 2), 'Wrong types of pgp keys pair'
            pub_key = kl.decrypt_buf_by_kmi_ladder(key1[2], user_id)
            priv_key = kl.decrypt_buf_by_kmi_ladder(key2[2], user_id)
        else:
            assert (key1[3] == 2), 'Wrong types of pgp keys pair'
            pub_key = kl.decrypt_buf_by_kmi_ladder(key2[2], user_id)
            priv_key = kl.decrypt_buf_by_kmi_ladder(key1[2], user_id)
    else:
        key1,key2 = sqlalchemy.session.query(UserKey.ukey_id, UserKey.ukey_name, UserKey.ukey_value, UserKey.uktp_uktp_id,  UserKey.ukey_ukey_id, UserKey.ukey_email, UserKey.ukey_comment, UserKey.ukey_expires).filter(UserKey.pttp_pttp_id==pttp_id).all()
        if key1[3] == 1:
            assert (key2[3] == 2), 'Wrong types of pgp keys pair'
            pub_key = kl.decrypt_buf_by_kmi_ladder(key1[2], pttp_id)
            priv_key = kl.decrypt_buf_by_kmi_ladder(key2[2], pttp_id)
        else:
            assert (key1[3] == 2), 'Wrong types of pgp keys pair'
            pub_key = kl.decrypt_buf_by_kmi_ladder(key2[2], pttp_id)
            priv_key = kl.decrypt_buf_by_kmi_ladder(key1[2], pttp_id)
    db_exp_time = int(calendar.timegm(key1[7].timetuple()))

    print 'db_exp_time: %s' % db_exp_time
    assert (key1[7] == key2[7] and db_exp_time == expires_time), 'Wrong expires_time for user=%s and pttp=%s' % (user_id, pttp_id)
    assert (key1[0] == key2[4]), 'Wrong link public and private key for user=%s and pttp=%s' % (user_id, pttp_id)
    assert (key1[4] == key2[0]), 'Wrong link public and private key for user=%s and pttp=%s' % (user_id, pttp_id)

    import_res_pub = gpg.import_keys(pub_key)
    #assert (import_res_pub.counts['count'] == 1), 'Wrong number keys in public key for user=%s and pttp=%s' % (user_id, pttp_id)
    assert ('secret' not in import_res_pub.results[0]['status']), 'Wrong type of public key for user=%s and pttp=%s' % (user_id, pttp_id)
    import_res_priv = gpg.import_keys(priv_key)
    #assert (import_res_priv.counts['count'] == 1), 'Wrong number keys in private key for user=%s and pttp=%s' % (user_id, pttp_id)
    assert ('private' in import_res_priv.results[0]['status']), 'Wrong type of public key for user=%s and pttp=%s' % (user_id, pttp_id)

    return 1

def check_hash(db, blbx_name, path_to_file):
    id = db.session.query(BlackBox.blbx_id).filter(BlackBox.blbx_name == blbx_name).one()[0]
    kmbk = db.session.query(BlackBoxLadderKeys.kmbk_value).filter(BlackBoxLadderKeys.blbx_blbx_id == id).one()[0]
    hash_from_db = hashlib.sha256(kmbk).hexdigest()
    hash_from_kmi = open(path_to_file).read()
    assert(hash_from_db == hash_from_kmi), "Hash from db and kmi is not equal"
    return 1

def get_number_keys_for_pttp(sqlalchemy, pttp_id):
    return len(sqlalchemy.session.query(UserKey).filter(UserKey.del_date==None, UserKey.pttp_pttp_id==pttp_id).all())


def get_pttp_with_pgp(db):
    return random.choice(list(set(db.session.query(UserKey.pttp_pttp_id).filter(UserKey.pttp_pttp_id!=None, UserKey.del_date==None).all()))[0])


def check_exported_public_key(db, key_id, pttp_id, output_filename):
    full_path_to_file = os.path.join(KmiHelper.get_homedir_out(), output_filename)
    if pttp_id == 0:
        db_public_key = db.session.query(UserKey.ukey_value, UserKey.user_user_id).filter(UserKey.ukey_ukey_id==key_id, UserKey.del_date==None, UserKey.uktp_uktp_id==1).one()
    else:
        db_public_key = db.session.query(UserKey.ukey_value, UserKey.pttp_pttp_id).filter(UserKey.pttp_pttp_id==pttp_id, UserKey.del_date==None, UserKey.uktp_uktp_id==1).one()
    with open(full_path_to_file) as file:
        key_data = file.read()
        db_key_data = kl.decrypt_buf_by_kmi_ladder(db_public_key[0],db_public_key[1] )
        assert(key_data==db_key_data), 'Wrong exported public key for pttp=%s' % pttp_id
    return 1


def get_public_user_key_id(db):
    return random.choice(list(set(db.session.query(UserKey.ukey_id).filter(UserKey.user_user_id!=None, UserKey.uktp_uktp_id==1).all()))[0])


def get_private_pgp_key(db):
    return random.choice(list(set(db.session.query(UserKey.ukey_id).filter( UserKey.uktp_uktp_id==2).all()))[0])

def check_user_keys(db, key_list, user_id):
    db_key_list = db.session.query(UserKey.ukey_id,UserKey.ukey_name, UserKey.ukey_value, UserKey.uktp_uktp_id, UserKey.ukey_email, UserKey.ukey_expires).filter(UserKey.del_date==None,UserKey.user_user_id==user_id).all()
    assert(len(db_key_list) == len(key_list)), 'Wrong number keys from DB and kmi for user=%s' % user_id
    if len(key_list)==0:
        return 1
    for key in key_list:
        i = 0
        for db_key in db_key_list:
            i += 1
            if key.keyId==db_key[0]:
                if key.keyName==db_key[1]and key.keyValue==kl.decrypt_buf_by_kmi_ladder(db_key[2],user_id) and key.keyType==db_key[3] and key.keyEmail==db_key[4] and key.keyExpires==calendar.timegm(db_key[5].timetuple()):
                    break
                else:
                    log('ERROR::Wrong key_list for user %s and key_id %s' % (user_id, db_key[0]))
                    return 0
    log('check_user_keys SUCCESS')
    return 1


def get_any_user_id_with_keys(db):
    return random.choice(list(set(db.session.query(UserKey.user_user_id).filter(UserKey.user_user_id!=None, UserKey.del_date == None).all()))[0])


def get_generated_user_keyid(db, user_id):
    return random.choice(db.session.query(UserKey.ukey_id).filter(UserKey.del_date == None, UserKey.user_user_id==user_id, UserKey.ukey_id!=UserKey.ukey_ukey_id).all())[0]


def is_pgp_key_deleted(db, key_id):
    linked_key_id=db.session.query(UserKey.ukey_ukey_id).filter(UserKey.ukey_id==key_id).one()[0]
    if key_id==linked_key_id:
        db.session.query(UserKey).filter(UserKey.del_date != None, UserKey.ukey_ukey_id==key_id).one()
    else:
        db.session.query(UserKey).filter(UserKey.del_date != None, UserKey.ukey_ukey_id==key_id).one()
        db.session.query(UserKey).filter(UserKey.del_date != None, UserKey.ukey_id==key_id).one()
    return 1

