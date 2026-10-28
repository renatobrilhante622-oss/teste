"""Minimal ES3 edit. Zero suffix is experimental and breaks standard AES-CBC reading.
Use --padding json-spaces for valid JSON/PKCS7 at the requested total size.
Neither mode recalculates SystemInfo or establishes game acceptance.
"""
import argparse, copy, getpass, hashlib, json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from editar_preservando_conta import value_span

def decrypt(blob, password):
    key = hashlib.pbkdf2_hmac('sha1', password, blob[:16], 100, 16)
    d = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
    data = d.update(blob[16:]) + d.finalize()
    u = PKCS7(128).unpadder()
    return u.update(data) + u.finalize()

def edit(blob, password, padding):
    raw = decrypt(blob, password)
    text = raw.decode('utf-8-sig')
    root = json.loads(text)
    before = json.loads(root['PlayerSaveData']['value'])
    p = copy.deepcopy(before)
    next(x for x in p['currenySaveDatas'] if x['Key'] == 100001)['Quantity'] = 99999999
    slot = next(x for x in p['stashSaveDatas'] if x['Index'] == 0)
    uid = slot['ItemUniqueId']
    if not uid: raise ValueError('Slot 0 has no existing record to replace')
    index = next(i for i,x in enumerate(p['itemSaveDatas']) if x['UniqueId'] == uid)
    # Reuse the slot's existing record and UID. No array entries added.
    template = next(x for x in p['itemSaveDatas'] if x['ItemKey'] == 190004)
    item = copy.deepcopy(template)
    item['UniqueId'] = uid
    p['itemSaveDatas'][index] = item
    slot['Quantity'] = 99
    for k in before:
        if k not in {'currenySaveDatas','stashSaveDatas','itemSaveDatas'}:
            assert p[k] == before[k]
        if isinstance(before[k], list): assert len(before[k]) == len(p[k])
    for x,y in zip(before['stashSaveDatas'],p['stashSaveDatas']):
        if x['Index'] != 0: assert x == y
    for i,(x,y) in enumerate(zip(before['itemSaveDatas'],p['itemSaveDatas'])):
        if i != index: assert x == y
    wrapper = copy.deepcopy(root['PlayerSaveData'])
    wrapper['value'] = json.dumps(p,ensure_ascii=False,separators=(',',':'))
    a,b = value_span(text,'PlayerSaveData')
    changed = text[:a] + json.dumps(wrapper,ensure_ascii=False,separators=(',',':')) + text[b:]
    for name in ['AccountSaveData','SystemInfo']:
        c,d = value_span(text,name); e,f = value_span(changed,name)
        assert text[c:d] == changed[e:f]
    output_root = json.loads(changed)
    for k in root:
        if k != 'PlayerSaveData': assert root[k] == output_root[k]
    plain = (b'\xef\xbb\xbf' if raw.startswith(b'\xef\xbb\xbf') else b'') + changed.encode('utf-8')
    target = 262144
    if padding == 'json-spaces':
        capacity = target - 17
        if len(plain) > capacity: raise ValueError('JSON does not fit; refusing to truncate')
        plain += b' ' * (capacity-len(plain))
    iv = blob[:16]
    key = hashlib.pbkdf2_hmac('sha1',password,iv,100,16)
    pad = PKCS7(128).padder(); padded = pad.update(plain) + pad.finalize()
    enc = Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor()
    encrypted = iv + enc.update(padded) + enc.finalize()
    assert json.loads(decrypt(encrypted,password).decode('utf-8-sig')) == output_root
    encrypted_length = len(encrypted)
    if encrypted_length > target: raise ValueError('Encrypted data does not fit')
    if padding == 'zeros': encrypted += b'\x00' * (target-len(encrypted))
    assert len(encrypted) == target and encrypted[:16] == iv
    report = {'bytes':len(encrypted),'encrypted_prefix_bytes':encrypted_length,
              'zero_suffix_bytes':len(encrypted)-encrypted_length,
              'padding':padding,'account_and_systeminfo_exact':True,
              'same_iv':True,'array_lengths_unchanged':True,
              'gold':99999999,'stash_index':0,'ItemKey':190004,'Quantity':99,
              'warning':'Game acceptance not verified; 99 exceeds user-reported stack limit of 5. SystemInfo not recalculated.'}
    if padding == 'zeros':
        try:
            recovered = decrypt(encrypted,password)
            json.loads(recovered.decode('utf-8-sig'))
        except (ValueError,UnicodeError):
            report['full_file_standard_decrypt_and_json'] = 'FAILED: zero suffix is not valid ES3 padding'
        else: report['full_file_standard_decrypt_and_json'] = 'passed'
    else: report['full_file_standard_decrypt_and_json'] = 'passed'
    return encrypted, report

if __name__ == '__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('original',type=Path); ap.add_argument('output',type=Path)
    ap.add_argument('--padding',choices=['zeros','json-spaces'],default='zeros')
    args=ap.parse_args()
    password=getpass.getpass('Senha ES3: ').encode('utf-8')
    result,report=edit(args.original.read_bytes(),password,args.padding)
    with args.output.open('xb') as f: f.write(result)
    print(json.dumps(report,ensure_ascii=False,indent=2))
