"""Edit only gold and 40 new five-unit Soulstone packs. Requires cryptography.
Never overwrites the source. Refuses size overflow rather than truncating data.
Integrity/game compatibility must be validated separately.
"""
import argparse, copy, hashlib, json, os, getpass
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

PASSWORD = None

def decrypt(blob):
    iv = blob[:16]
    key = hashlib.pbkdf2_hmac('sha1', PASSWORD, iv, 100, 16)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(blob[16:]) + dec.finalize()
    unpad = PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()

def value_span(text, wanted):
    """Locate a root value without reserializing other root data."""
    decoder = json.JSONDecoder()
    i = text.index('{') + 1
    while True:
        while text[i].isspace() or text[i] == ',': i += 1
        if text[i] == '}': raise KeyError(wanted)
        key, i = decoder.raw_decode(text, i)
        while text[i].isspace(): i += 1
        if text[i] != ':': raise ValueError('Invalid JSON')
        i += 1
        while text[i].isspace(): i += 1
        start = i
        _, i = decoder.raw_decode(text, i)
        if key == wanted: return start, i

def modify(original, gold=None, target_size=None):
    raw = decrypt(original)
    if raw.startswith(b'\x1f\x8b'):
        raise ValueError('GZip input requires a separate, verified path.')
    text = raw.decode('utf-8-sig')
    root = json.loads(text)
    before = json.loads(root['PlayerSaveData']['value'])
    player = copy.deepcopy(before)
    if gold is not None:
        entry = next(x for x in player['currenySaveDatas'] if x['Key'] == 100001)
        entry['Quantity'] = gold
    slots = [x for x in player['stashSaveDatas']
             if not x['ItemUniqueId'] and x.get('IsUnLock', False)
             and not x.get('IsBlocked', False)]
    if len(slots) < 40: raise ValueError('Fewer than 40 empty unlocked storage slots')
    template = next((x for x in player['itemSaveDatas'] if x['ItemKey'] == 190004), None)
    if template is None: raise ValueError('No original Soulstone record to copy')
    uid = max(x['UniqueId'] for x in player['itemSaveDatas'])
    for slot in slots[:40]:
        uid += 1
        item = copy.deepcopy(template)
        item.update(UniqueId=uid, PrevUniqueId=0, IsBlocked=False, RegisterID='')
        player['itemSaveDatas'].append(item)
        slot.update(ItemUniqueId=uid, Quantity=5)
    # Only these player sections may differ. No hero/session edits.
    for k in before:
        if k not in {'currenySaveDatas', 'stashSaveDatas', 'itemSaveDatas'}:
            assert before[k] == player[k], k
    wrapper = copy.deepcopy(root['PlayerSaveData'])
    wrapper['value'] = json.dumps(player, ensure_ascii=False, separators=(',', ':'))
    start, end = value_span(text, 'PlayerSaveData')
    replacement = json.dumps(wrapper, ensure_ascii=False, separators=(',', ':'))
    edited = text[:start] + replacement + text[end:]
    # Account block and all other outer bytes are preserved, not reserialized.
    a, b = value_span(text, 'AccountSaveData')
    c, d = value_span(edited, 'AccountSaveData')
    assert text[a:b] == edited[c:d]
    checked = json.loads(edited)
    for k in root:
        if k != 'PlayerSaveData': assert root[k] == checked[k], k
    plain = (b'\xef\xbb\xbf' if raw.startswith(b'\xef\xbb\xbf') else b'') + edited.encode('utf-8')
    size = len(original) if target_size is None else target_size
    if size < 32 or (size - 16) % 16:
        raise ValueError('Size must include a 16-byte IV and whole AES blocks')
    # JSON trailing spaces are valid; never insert bytes after AES ciphertext.
    capacity = size - 16 - 1  # at least one byte of PKCS7 padding
    if len(plain) > capacity:
        raise ValueError(f'Edited JSON needs {len(plain)} bytes; target capacity is {capacity}. '
                         'Cannot preserve this size without removing data or changing format.')
    plain += b' ' * (capacity - len(plain))
    iv = original[:16]
    key = hashlib.pbkdf2_hmac('sha1', PASSWORD, iv, 100, 16)
    pad = PKCS7(128).padder()
    padded = pad.update(plain) + pad.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    result = iv + enc.update(padded) + enc.finalize()
    assert len(result) == size and result[:16] == original[:16]
    assert json.loads(decrypt(result).decode('utf-8-sig')) == checked
    return result

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('original', type=Path)
    ap.add_argument('output', type=Path)
    ap.add_argument('--gold', type=int)
    ap.add_argument('--target-size', type=int, help='Default: actual source size, not an assumed 256 KB')
    args = ap.parse_args()
    PASSWORD = (os.environ.get('ES3_SAVE_PASSWORD') or getpass.getpass('Senha ES3: ')).encode('utf-8')
    if args.gold is not None and args.gold < 0: ap.error('Gold must be nonnegative')
    if args.original.resolve() == args.output.resolve(): ap.error('Output must differ from source')
    result = modify(args.original.read_bytes(), args.gold, args.target_size)
    with args.output.open('xb') as f: f.write(result)
    print('Created; IV and account preserved. Game integrity/acceptance NOT verified.')
