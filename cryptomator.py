import os
import jwt
import json
import hashlib
import base64
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers.aead import AESSIV, AESGCM
from enum import Enum
from io import BufferedReader, BufferedWriter, BytesIO

# clearmem dummy function
# TODO import real clearmem function
def clearmem(s: str|bytes):
    ''' clear the memory of a string or bytes object '''
    pass

def splitall(path):
    # TODO check
    ''' thanks to https://www.oreilly.com/library/view/python-cookbook/0596001673/ch04s16.html'''
    allparts = []
    while 1:
        parts = os.path.split(path)
        if parts[0] == path:  # sentinel for absolute paths
            allparts.insert(0, parts[0])
            break
        elif parts[1] == path: # sentinel for relative paths
            allparts.insert(0, parts[1])
            break
        else:
            path = parts[0]
            allparts.insert(0, parts[1])
    return allparts

# some shortcuts
pj = os.path.join

VAULT_FILE_NAME = 'vault.cryptomator'
MASTERKEY_FILE_NAME = 'masterkey.cryptomator'
DIRID_FILE_NAME = 'dirid.c9r'   # parent id, encrypted like other files
DIR_FILE_NAME = 'dir.c9r'   # folders id, plain bytes, ascii
CONTENT_FILE_NAME = 'contents.c9r'   # file content
SYMLINK_FILE_NAME = 'symlink.c9r'   # symlink
SHORTENING_FILE_NAME = 'name.c9s'   # shortend name
DATA_FOLDER = 'd'

VAULT_PATH_ROOT_DEPRICATED = 'vault:/'
VAULT_PATH_ROOT_PREFIX = 'vault:'

FILE_EXT_CRYPTOR = '.c9r'
FILE_EXT_SORTEND = '.c9s'

ROOT_DIR_ID = b''

MAX_DIRID_LENGTH = 256

CLI_CMD_CAT_MAX_SIZE = 1024

# JWT
JWT_KID = f'masterkeyfile:{MASTERKEY_FILE_NAME}'
JWT_TYPE = 'JWT'
JWT_ALGORITHM = 'HS256'

VAULT_VERSION = 8

KEK_NUM_BYTES = 32  
SCRYPT_MAX_MEMORY = 64 * 1024 * 1024
SALT_SIZE = 8
WRAPPED_PMK_LEN = 40
WRAPPED_HMK_LEN = 40
VMAV_SIZE = 32
UNWRAPPED_PMK_LEN = 32
UNWRAPPED_HMK_LEN = 32


class CipherCombo(Enum):
    SIV_GCM = 'SIV_GCM'
    SIV_CTRMAC = 'SIV_CTRMAC'


class Common:

    @staticmethod
    def is_base64url(s: str):
        # TODO move to utils class
        # TODO use decoder decode
        valid_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_='
        return all([
            c in valid_chars for c in s
        ])
    
    @staticmethod
    def decrypt_filename(name_b64: str, parent_id: bytes, masterkey: 'Masterkey') -> str:
        '''
            ciphertextName := base64url(aesSiv(cleartextName, parentDirId, encryptionMasterKey, macMasterKey)) + '.c9r'

            https://docs.cryptomator.org/en/latest/security/vault/#filename-encryption
            https://github.com/cryptomator/cryptolib/blob/2.2.0/src/main/java/org/cryptomator/cryptolib/v2/FileNameCryptorImpl.java

            ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
            byte[] encryptedBytes = encoding.decode(ciphertextName);
            byte[] cleartextBytes = siv.get().decrypt(ek, mk, encryptedBytes, associatedData);
            return new String(cleartextBytes, UTF_8);
        '''
        key = masterkey.hmac + masterkey.primary
        name_bytes = base64.urlsafe_b64decode(name_b64)
        name = AESSIV(key).decrypt(name_bytes, [parent_id])
        
        # TODO explicitly destroy keys etc
        # https://pypi.org/project/SecureBytes/
        # https://pypi.org/project/SecureString/
        
        return name.decode('utf-8')
    
    
    @staticmethod
    def decrypt_file(reader: BufferedReader, writer: BufferedWriter, primary_key: bytes, combo: CipherCombo) -> bytes|BufferedWriter:
        ''' decrypts a file from bytes or reader to a writer or returns the decrypted data
        
            headerNonce := createRandomBytes(12)
            contentKey := createRandomBytes(32)
            cleartextPayload := 0xFFFFFFFFFFFFFFFF . contentKey
            ciphertextPayload, tag := aesGcm(cleartextPayload, encryptionMasterKey, headerNonce)

            SIV_GCM for > 1.6
            SIV_CTRMAC for <= 1.6

            ? https://datatracker.ietf.org/doc/html/rfc5288
            https://docs.cryptomator.org/en/latest/security/vault/#file-encryption
            https://en.wikipedia.org/wiki/Galois/Counter_Mode
            https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM
            https://github.com/cryptomator/cryptolib/blob/2.2.0/src/main/java/org/cryptomator/cryptolib/v2/FileHeaderCryptorImpl.java
        '''
        # raise if not supportde cipher combo
        if combo is not CipherCombo.SIV_GCM:
            raise Exception('Cipher combo not supported')
        
        # TODO implement buffered processing

        # decrypt header
        # TODO check data length format etc
        # TODO no magic numbers
        header = reader.read(68)
        header_nonce = header[:12]
        crypted = header[12:52]
        tag = header[52:68]
        ct = crypted + tag
        if not all([
            len(header_nonce) == 12,
            len(crypted) == 40,
            len(tag) == 16,
            len(ct) == 56
        ]):
            raise Exception('Invalid file header bytemapping')

        cipher = AESGCM(primary_key)
        clearmem(primary_key)
        payload = cipher.decrypt(header_nonce, ct, None)
        # TODO delete cipher data and its data
        del cipher
        ones = payload[:8]
        content_key = payload[8:]
        if not all([
            ones == b'\xff' * 8,
            len(content_key) == 32
        ]):
            raise Exception('Invalid file header content')
        
        # chunk file content
        # TODO merge steps later if all works
        remaining = reader.read()
        max_chunksize = 32 * 1024 + 28
        min_chunksize = 28 + 1
        decrypted = bytes()
        cipher = AESGCM(content_key)
        clearmem(content_key)
        for i in range(0, len(remaining), max_chunksize):
            number = i // max_chunksize
            chunk = remaining[i:i+max_chunksize]
            if len(chunk) < min_chunksize or len(chunk) > max_chunksize:
                raise Exception('Invalid chunk size')
            
            content_nonce = chunk[:12]
            crypted = chunk[12:-16]
            tag = chunk[-16:]

            aad = number.to_bytes(8, 'big') + header_nonce
            clear_chunk = cipher.decrypt(content_nonce, crypted + tag, aad)
            if not all([
                len(clear_chunk) == len(crypted)
            ]):
                raise Exception('Decrypted chunk size mismatch')
            decrypted += clear_chunk
        # TODO delete cipher data and its data
        del cipher
        clearmem(primary_key)

        # return decrypted data
        r = decrypted
        if writer:
            writer.write(decrypted)
            r = None

        return r


class Masterkey:
    '''
        reads masterkey file and decodes its data with given password
        
        https://docs.cryptomator.org/en/latest/security/architecture/
        https://datatracker.ietf.org/doc/html/rfc7914
        https://datatracker.ietf.org/doc/html/rfc3394
        https://docs.python.org/3/library/hashlib.html
        https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/Scrypt.java
        password is utf8 encoded 
            -> https://github.com/cryptomator/cryptolib/blob/b04101c375925a9274b8c69a95987ea075186d3e/src/main/java/org/cryptomator/cryptolib/common/Scrypt.java#L29
        https://datatracker.ietf.org/doc/html/rfc3394
        https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/common/AesKeyWrap.java

        encryptionMasterKey := createRandomBytes(32)
        macMasterKey := createRandomBytes(32)
        kek := scrypt(password, scryptSalt, scryptCostParam, scryptBlockSize)
        wrappedEncryptionMasterKey := aesKeyWrap(encryptionMasterKey, kek)
        wrappedMacMasterKey := aesKeyWrap(macMasterKey, kek)
    '''
    
    RELEVANT_PARAMS = [
        'scryptSalt',
        'scryptCostParam',
        'scryptBlockSize',
        'primaryMasterKey',
        'hmacMasterKey',
        'versionMac'
    ]

    def __init__(self, path: str, password: str):
        # init defaults
        self._path: str = path          # masterkey file path
        self._json: object = None       # masterkey file data
        self._kek: bytes = None         # key encryption key
        self._salt: bytes   = None      # scrypt salt
        self._cost: int = None          # scrypt cost param
        self._blocksize: int = None     # scrypt block size
        self._wrapped_pmk: bytes  = None       # aes wrapped primary master key
        self._wrapped_hmk: bytes = None        # aes wrapped hmac master key
        self._vmac: bytes  = None       # version mac
        self._pmk: bytes = None         # primary master key
        self._hmk: bytes = None         # hmac master key
        
        # TODO get rid of key leaks in memory
        # https://pypi.org/project/SecureBytes/
        # https://pypi.org/project/SecureString/

        # read masterkey file and decode json
        with open(self._path, 'r') as file:
            content = file.read()
        obj = json.loads(content)
        
        # store relevant fields
        self._json = {k: obj[k] for k in self.RELEVANT_PARAMS}
        
        # decode data
        self._salt = base64.b64decode(self._json['scryptSalt'])
        self._cost = self._json['scryptCostParam']        
        self._blocksize = self._json['scryptBlockSize']
        self._wrapped_pmk = base64.b64decode(self._json['primaryMasterKey'])
        self._wrapped_hmk = base64.b64decode(self._json['hmacMasterKey'])
        self._vmac = base64.b64decode(self._json['versionMac'])
        if not all([
            self._blocksize > 0,
            self._cost & (self._cost - 1) == 0,     # must be power of 2
            self._cost > 2,
            self._cost < pow(2, 128 * self._blocksize / 8),
            len(self._salt) == SALT_SIZE,
            len(self._wrapped_pmk) == WRAPPED_HMK_LEN,
            len(self._wrapped_hmk) == WRAPPED_PMK_LEN,
            len(self._vmac) == VMAV_SIZE
        ]):
            raise Exception('Invalid masterkey file')

        # derive kek from password and given params
        scrypt_params = {
            'salt': self._salt,
            'n': self._cost,
            'r': self._blocksize,
            'p': 1,
            'maxmem': SCRYPT_MAX_MEMORY,
            'dklen': KEK_NUM_BYTES
        }
        self._kek = hashlib.scrypt(bytes(password, 'utf-8'), **scrypt_params)
        if len(self._kek) != KEK_NUM_BYTES:
            raise Exception('Invalid kek length')
        clearmem(password)
        
        # unwrap primary master key
        self._pmk = keywrap.aes_key_unwrap(self._kek, self._wrapped_pmk)
        self._hmk = keywrap.aes_key_unwrap(self._kek, self._wrapped_hmk)
        if not all([
            len(self._pmk) == UNWRAPPED_PMK_LEN,
            len(self._hmk) == UNWRAPPED_HMK_LEN
        ]):
            raise Exception('Unwrapping key failed')
    
    @property
    def primary(self) -> bytes:
        return self._pmk
    
    @property
    def hmac(self) -> bytes:
        return self._hmk
    
    @property
    def path(self) -> str:
        return self._path


class Directory:

    @staticmethod
    def parse_index(vault: 'Vault') -> tuple[dict['Directory'], 'Directory']:
        ''' parse vaults directory index '''
        dirs = {}
        data_path = vault.data_path
        root = None
        
         # read directory index
        for idx in os.listdir(data_path):
            for entry in os.listdir(os.path.join(data_path, idx)):
                dir_hash = idx + entry
                dir = Directory(vault, dir_hash)
                dirs[dir_hash] = dir  
                if dir.is_root():
                    root = dir 
                

        return dirs, root
    
    @staticmethod
    def path_by_id(vault: 'Vault', dir_id: bytes):
        dir_hash = Directory.hash_id(dir_id, vault.masterkey)
        return Directory.path_by_hash(vault, dir_hash)

    @staticmethod
    def hash_id(dir_id: bytes, masterkey: 'Masterkey') -> str:
        '''
            IV is generated from left most key S2V, here hmac masterkey
            right most key is used for encryption
            ! cryptomator JWT key is right <-> left               

            https://docs.cryptomator.org/en/latest/security/vault/#directory-ids
                -> dirIdHash := base32(sha1(aesSiv(dirId, null, encryptionMasterKey, macMasterKey)))

            https://github.com/cryptomator/siv-mode
            https://datatracker.ietf.org/doc/html/rfc5297
            https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESSIV

        '''
        # TODO pass bytes instead of masterkey
        key = masterkey.hmac + masterkey.primary
        crypted = AESSIV(key).encrypt(dir_id, None)
        hash_bytes = hashlib.sha1(crypted).digest()
        hash_b32 = base64.b32encode(hash_bytes).decode('utf-8')
        return hash_b32
    
    @staticmethod
    def path_by_hash(vault: 'Vault', hash: str):
        '''
            https://docs.cryptomator.org/en/latest/security/vault/#directory-ids
                -> dirPath := vaultRoot + '/d/' + substr(dirIdHash, 0, 2) + '/' + substr(dirIdHash, 2, 30)
        '''
        return os.path.join(vault.data_path, hash[:2], hash[2:])

    def __init__(self, vault: 'Vault', hash: str):
        # defaults
        self._vault = vault
        self._hash = hash
        self._path = Directory.path_by_hash(vault, hash)
        self._dirid_path = pj(self._path, DIRID_FILE_NAME)
        self._parent_id = None
        self._nodes: list[Node] = []                    

        # read parent id from dirid file
        with open(self._dirid_path, 'rb') as src:
            self._parent_id = Common.decrypt_file(src, None, self._vault.masterkey.primary, self._vault.cipher_combo)
            
        # scan for valid node pathes
        pathes = [pj(self._path, e) for e in os.listdir(self._path) if all([
            e != DIRID_FILE_NAME,
            e.endswith(FILE_EXT_CRYPTOR) or e.endswith(FILE_EXT_SORTEND)
        ])]
        
        # create actual nodes
        for p in pathes:
            n = Node(vault, self._parent_id, p)
            self._nodes.append(n)
            
    @property
    def path(self):
        return self._path
    
    @property
    def nodes(self):
        return self._nodes
            
    def is_root(self):
        return self._parent_id == ROOT_DIR_ID
    
    def node_by_name(self, name: str, category: str) -> 'Node':
        ''' find node by name and category '''
        
        found = [n for n in self._nodes if n.clear_name == name and n.category == category]
        
        return found[0] if found else None

class Index:
    ''' cached index of all directories and nodes '''

    def __init__(self, vault: 'Vault'):
        self._vault: Vault = vault
        self._dirs: dict[str, 'Directory'] = {}
        self._root: 'Directory' = None
        self._tree: list[Node] = []

    def rebuild(self):
        ''' rebuild complete '''
        # TODO make notifiable or partial update

        # read all directories from filesystem
        self._dirs, self._root = Directory.parse_index(self._vault)
        
        # tree builder by childs
        def _proc_childs(parent: Node|None, childs: list[Node]):
            for n in childs:
                n.parent = parent
                if n.category == 'dir':
                    # HINT reference is stored -> dir eand tree childs are in sync
                    n.childs = self._dirs[n.dir_hash]._nodes
                    n.childs.sort(key=_sort)
                    if n.childs:
                        _proc_childs(n, n.childs)

        # sort function
        def _sort(node: Node):
            # handle symlink as file
            cat = 0 if node.category == 'dir' else 1
            return (cat, node.clear_name)

        # build tree
        self._tree = self._root.nodes
        self._tree.sort(key=_sort)
        _proc_childs(None, self._tree)
        
        return
    
    def dump_tree(self, what: str = 'clear_name'):
        ''' print tree structure '''

        # recursive print function
        def _print_node(node: Node, level: int):
            to_print = getattr(node, f'_{what}')
            print('...' * level + ' ' + str(to_print))
            for n in node.childs:
                _print_node(n, level + 1)
        
        # print root -> recursive childs
        title = f"Vault: {self._vault.uuid}"
        print(f"\n{title}")
        print('=' * len(title))
        for n in self._tree:
            _print_node(n, 1)
        print('\n')

        return

    def _split_path(self, path: str) -> tuple[list['str'],str]:
        ''' split path into dirnames and filename 
        
            path can be:
            - absolute linux path, "/path/to/file"
            - absolute windows path, "C:/path/to/file"
            - absolute vault path, "vault:/path/to/file"
        '''
        # handle different path types        
        if path.startswith(VAULT_PATH_ROOT_DEPRICATED):
            path = path[len(VAULT_PATH_ROOT_DEPRICATED):]
        elif path.startswith('/'):
            raise NotImplementedError('Posix path')
        elif path.startswith('C:/'):
            raise NotImplementedError('Windows path')
        else:
            raise Exception('Invalid path')

        # split dirs and files
        dirnames = path.split('/')
        filename = dirnames.pop(-1)

        return dirnames, filename
    
    def nodes_by_path(self, path: str) -> tuple[list['Node'], bool]|None:
        ''' lists nodes at given absolute path. root can be vault, posix or windows path '''

        # split dirs and files, process only folders
        dirnames, filename = self._split_path(path)
        is_file = filename != ''

        # handle cached or not
        # TODO handle cached or not
        self.rebuild()
        
        # find dir of path
        work = dirnames[:]
        dir = self._root
        while work:
            dirname = work.pop(0)
            node = dir.node_by_name(dirname, 'dir')
            if not node:
                dir = None
                break;
            dir = self._dirs[node.dir_hash]
        if not dir:
            return None
        
        # found nodes of dir
        nodes = dir.nodes

        # filter for file if needed
        if is_file:
            node = dir.node_by_name(filename, 'file')
            if node:
                nodes = [node]
            else:
                nodes = None
                
        return nodes, is_file

class Node:

    @staticmethod
    def is_node_name(path: str):
        ''' check if path has a valid node name '''
        basename = os.path.basename(path)
        name = basename.split('.')[0]
        ext = f".{basename.split('.')[1]}"
        if os.path.isfile(path):
            return all([
                ext in [FILE_EXT_CRYPTOR],
                Common.is_base64url(name)
            ])
        elif os.path.isdir(path):
            return all([
                ext in [FILE_EXT_CRYPTOR, FILE_EXT_SORTEND],
                Common.is_base64url(name)
            ])
        else:
            # should never happen
            return False

    def __init__(self, vault: 'Vault', parent_id: bytes, path: str) -> None:
        # raise if not a valid node name
        if not self.is_node_name(path):
            raise Exception('Invalid node name')
        
        # defaults
        self._vault = vault
        self._parent_id = parent_id
        self._path = path
        self._basename = os.path.basename(path)
        self._name = self._basename.split('.')[0]
        self._extension = self._basename.split('.')[1]
        self._is_file = os.path.isfile(self._path)
        self._is_dir = os.path.isdir(self._path)
        self._is_shortend = all([
            self._basename.endswith(FILE_EXT_SORTEND),
            self._is_dir,
            self._is_dir and os.path.isfile(os.path.join(self._path, SHORTENING_FILE_NAME)),
        ])
        self._category: str = None       # category of node (file, dir, symlink)
        self._clear_name: str = None     # nodes clear name
        self._dir_id: bytes = None      # nodes dir_id if it is a dir
        self._dir_hash: str = None      # nodes dir_hash if it is a dir
        self._dir_path: str = None      # nodes absolute path in directory index (vault/d/) if it is a dir

        # public tree properties
        self.parent: Node = None         # parent node in tree
        self.childs: list[Node] = []     # child nodes in tree
        
        # select category
        if self._is_file or all([
            self._is_dir,
            self._is_dir and os.path.isfile(os.path.join(self._path, CONTENT_FILE_NAME))
        ]):
            self._category = 'file'
        elif all([
            self._is_dir,
            self._is_dir and os.path.isfile(os.path.join(self._path, DIR_FILE_NAME))
        ]):
            self._category = 'dir' 
        elif all([
            self._is_dir,
            self._is_dir and os.path.isfile(os.path.join(self._path, SYMLINK_FILE_NAME))
        ]):
            self._category = 'symlink'
        else:
            raise Exception('Can not determine nodes category')
        
        # inti according to category
        if self._category == 'file':
            self._init_as_file()
        elif self._category == 'dir':
            self._init_as_dir()
        elif self._category == 'symlink':
            self._init_as_symlink()
        else:
            # should never happen
            raise Exception('Unknown category: ' + self._path)

    def _init_as_file(self):
        # read nodes name
        name_to_decrypt = self._name
        if self._is_shortend:
            with open(pj(self._path, SHORTENING_FILE_NAME), 'rb') as file:
                name_to_decrypt = file.read()
        self._clear_name = Common.decrypt_filename(name_to_decrypt, self._parent_id, self._vault.masterkey) # TODO pass just data needed

    
    def _init_as_dir(self):        
        # read nodes name
        name_to_decrypt = self._name
        if self._is_shortend:
            with open(pj(self._path, SHORTENING_FILE_NAME), 'rb') as file:
                name_to_decrypt = file.read()
        self._clear_name = Common.decrypt_filename(name_to_decrypt, self._parent_id, self._vault.masterkey) # TODO pass just data needed
        
        # read dirs id and calc it's hash & path
        with open(pj(self._path, DIR_FILE_NAME), 'rb') as file:
            self._dir_id = file.read()
        self._dir_hash = Directory.hash_id(self._dir_id, self._vault.masterkey)
        self._dir_path = Directory.path_by_hash(self._vault, self._dir_hash)
    
    def _init_as_symlink(self):
        raise NotImplementedError('Symlinks not implemented yet')
    
    def __repr__(self) -> str:
        return f"{self._category}:{self._clear_name if self._clear_name else self._name}"
    
    def __str__(self) -> str:
        return self._clear_name if self._clear_name else f'[encrypted]{self._name[:10]}***'
    
    @property
    def dir_hash(self):
        return self._dir_hash
    
    @property
    def clear_name(self):
        return self._clear_name
    
    @property
    def category(self):
        return self._category


class Vault:
    '''
        internal vault class to handle vault files
        
        https://pyjwt.readthedocs.io/en/latest/
        https://jwt.io/
        https://datatracker.ietf.org/doc/html/rfc7519
        https://auth0.com/docs/secure/tokens/json-web-tokens
    '''
    
    JWT_HEADER_PARAMS = [
        'kid', 
        'alg', 
        'typ'
    ]
    
    JWT_CLAIMS_PARAMS = [
        'format',
        'shorteningThreshold',
        'jti',
        'cipherCombo'
    ]

    def __init__(self, path: str):
        
        self._path: str = path               # vaults root path
        self._token_data: str = None
        self._jwt_header: object = None
        self._jwt_claims: object = None
        self._verified: bool = False
        self._masterkey: Masterkey = None
        self._format: int = None                    # version of vault
        self._short_threshold: int = None           # filename shortening threshold
        self._jti: str = None                       # vaults unique id, UUID
        self._cipher_combo: CipherCombo = None           # mode of operation for the block cipher. Other possible values are "SIV_CTRMAC"
        self._data_path: str = pj(self._path, DATA_FOLDER)  # vaults data path
        self._master_path: str = pj(self._path, MASTERKEY_FILE_NAME)  # vaults masterkey path
        self._vault_path: str = pj(self._path, VAULT_FILE_NAME)  # vaults masterkey path
        self._index: Index = Index(self)            # index of all directories and nodes
        
        # check if all pathes exist
        if not all([
            os.path.exists(self._path),
            os.path.exists(self._master_path),
            os.path.exists(self._vault_path)
        ]):
            raise Exception('Vault files/folders not found')

        # read unverified jwt token from file
        with open(self._vault_path, 'r') as file:
            self._token_data = file.read()

        # precheck unverified jwt token header
        header = jwt.get_unverified_header(self._token_data)
        self._jwt_header = {k: header[k] for k in self.JWT_HEADER_PARAMS}
        if not all([
            self._jwt_header['kid'] == JWT_KID,
            self._jwt_header['typ'] == JWT_TYPE,
            self._jwt_header['alg'] == JWT_ALGORITHM
        ]):
            raise Exception('Invalid jwt header')
        
        # pre-check unverified jwt payload
        claims = jwt.decode(self._token_data, options={'verify_signature': False})
        if claims['format'] != VAULT_VERSION:
            raise Exception('Invalid vault version')
        
    def _verify(self, masterkey: Masterkey):
        self._verified = False
        self._masterkey = masterkey
        
        # decode jwt payload
        key = masterkey.primary + masterkey.hmac
        claims = jwt.decode(self._token_data, key, algorithms=[JWT_ALGORITHM])
        
        # store and checke necessary claim
        self._jwt_claims = {k: claims[k] for k in self.JWT_CLAIMS_PARAMS}
        self._format = claims['format']
        self._short_threshold = claims['shorteningThreshold']
        self._jti = claims['jti']
        self._cipher_combo = CipherCombo(claims['cipherCombo'])

        # check for errors
        if not all([
            self._masterkey.path == pj(self._path, str(self._jwt_header['kid']).split(':')[1]),
            self._format == VAULT_VERSION,
            self._cipher_combo is CipherCombo.SIV_GCM
        ]):
            raise Exception('Unsupported vault version or cipher combo')
        
        # set verified flag
        self._verified = True

        return self._verified

    def unlock(self, password: str) -> 'Vault':
        
        # read masterkey file
        self._masterkey = Masterkey(self._master_path, password)
        clearmem(password)
        
        # unlock vault with master key
        self._verify(self._masterkey)

        # update index if verified
        if self._verified:
            self._index.rebuild()
        
        return self
    
    @property
    def index(self):
        return self._index
    
    @property
    def uuid(self):
        return self._jti

    @property
    def cipher_combo(self):
        return self._cipher_combo
        
    @property
    def unlocked(self):
        return self._verified
    
    @property
    def path(self):
        return self._path
    
    @property
    def data_path(self):
        return self._data_path
    
    @property
    def masterkey(self):
        return self._masterkey
    
    def read_dir_index(self) -> tuple[dict[str, 'Directory'], 'Directory']:
        # TODO use cached data
        return Directory.parse_index(self)
        
    
    def locate(self, path: str) -> str:
        ''' converts virtual path to actual cryptor path. 
        
            - absolute linux path, "/path/to/file"
            - absolute windows path, "C:/path/to/file"
            - absolute vault path, "vault:/path/to/file"
        '''    

        # handle different path rypes
        # TODO translate path function, reused below
        if path.startswith(VAULT_PATH_ROOT_DEPRICATED):
            path = path[len(VAULT_PATH_ROOT_DEPRICATED):]
        elif path.startswith('/'):
            raise NotImplementedError('Posix path')
        elif path.startswith('C:/'):
            raise NotImplementedError('Windows path')
        else:
            raise Exception('Invalid path')

        # split dirs and files
        dirnames = path.split('/')
        filename = dirnames.pop(-1)
        is_file = filename != ''

        # get root dir
        # TODO used cached data
        dirs, root = self.read_dir_index()
        
        # find dir of path
        work = dirnames[:]
        dir = root
        while work:
            dirname = work.pop(0)
            node = dir.node_by_name(dirname, 'dir')
            if not node:
                dir = None
                break;
            dir = dirs[node.dir_hash]
        if not dir:
            return ''
        
        # construct virtual path
        cryptor_path = dir.path
        if is_file:
            node = dir.node_by_name(filename, 'file')
            if node:
                cryptor_path = node._path
                
        return cryptor_path
    
class Cmd:
    # TODO use a lib for this. argparse a cli lib if exists
    # TODO rebuild using cmd, cmd2, Python Prompt Toolkit, click
    # TODO cmd2 with argparse
    pass
    
class Cli:
    ''' simple cmd interpreter to navigate through the vaults '''

    SEP = '/'

    def __init__(self, vault):
        self._vault: Vault = vault
        self._cwd = list()
    
    def _path_to_vault_str(self, path:list[str], *, no_prefix:bool = False) -> str:
        altered = self.SEP if no_prefix else VAULT_PATH_ROOT_DEPRICATED
        if path:
            altered += self.SEP.join(path)
            altered += self.SEP
        return altered

    def _set_cwd(self, cwd: list[str]) -> bool:
        done = False
        if len(cwd) > 0:
            cpath = self._vault.locate(self._path_to_vault_str(cwd))
            done = os.path.exists(cpath)
            if done:
                self._cwd = cwd[:]
        else:
            self._cwd.clear()
            done = True
        return done
    
    def _rollout_path(self, path: str, no_prefix: bool = False) -> str:
        ''' rolls out a cli path to a cryptor index path according to current cwd

            cwd = /one/two/

            /one/two -> vault:/one/two
            three/five -> vault:/one/two/three/four
        '''
        # TODO use this function for every passed pathes in cli. like cd. cd handle s only abs path

        # TODO use a lib for this

        if path.startswith(self.SEP):
            # nothing to do
            pass
        elif path.startswith('..'):
            # TODO implement level up
            raise NotImplementedError()
        else:
            path = self._path_to_vault_str(self._cwd, no_prefix=True) + path

        # append prefix if needed
        if not no_prefix:
            path = VAULT_PATH_ROOT_PREFIX + path
        
        return path
    
    def cmd_cwd(self, path: str = None):
        # TODO rebuild using rollout path
        if not path:
            print(self._path_to_vault_str(self._cwd, no_prefix=True))
        else:
            self.cmd_cd(path)

    def cmd_ls(self):
        # TODO use rollout path
        path = self._path_to_vault_str(self._cwd)
        nodes, is_file = self._vault.index.nodes_by_path(path)
        if is_file:
            print('Not a directory')
            return
        
        # list dirs and files
        if nodes:
            for n in nodes:
                prefix = ''
                if n.category == 'dir':
                    prefix = '[D]'
                elif n.category == 'file':
                    prefix = '[f]'
                elif n.category == 'symlink':
                    prefix = '[s]'
                else:
                    raise Exception('Unknown category')
                print(prefix + n.clear_name)
        else:
            print('Empty')
        pass

    def cmd_cat(self, path: str): 
        # rollout path 
        path = self._rollout_path(path, no_prefix=True)

        # check for valid path 
        if len(path) <= 0 or path[0] != self.SEP:
            print('File not found')
            return

        # alter path index format
        path = VAULT_PATH_ROOT_PREFIX + path
        nodes, is_file = self._vault.index.nodes_by_path(path)
        if not nodes or not is_file:
            print('File not found')
            return

        # get file and dump
        node = nodes[0]
        if node.category == 'file':
            # cap max file size
            filesize = os.path.getsize(node._path)
            if filesize > CLI_CMD_CAT_MAX_SIZE:
                print(f'File too big: {filesize / 1024 / 1024} / {CLI_CMD_CAT_MAX_SIZE / 1024 / 1024} MiB')
                return
            
            # read and decrypt file
            with open(node._path, 'rb') as reader:
                data = Common.decrypt_file(reader, None, self._vault.masterkey.primary, self._vault.cipher_combo)
                print(data.decode('utf-8'))
                return
        else:
            print('Not a file')

    def cmd_cd(self, path: str):
        # TODO rebuild using rollout path
        # empty path means root
        path = self.SEP if not path else path

        # .. means one up
        if path == '..':
            if len(self._cwd) > 0:
                self._cwd.pop(-1)
            print(self._path_to_vault_str(self._cwd, no_prefix=True))
            return

        # split path and process
        splitted = path.split(self.SEP)
        if len(splitted) > 0:
            if len(splitted) > 1:
                # remove last since file or empty
                splitted.pop(-1)

            # handle absolute or relative path
            cwd = self._cwd[:]
            if splitted[0] != '':
                cwd += splitted
            else:
                cwd = splitted[1:]

            # update cli's cwd
            if self._set_cwd(cwd):
                print(self._path_to_vault_str(self._cwd, no_prefix=True))
            else:
                print('Path not found')

    def cmd_help(self):        
        print('Commands:')
        print('  help - display this help')
        print('  ls - list directory')
        print('  cd - change directory')
        print('  cat - display file content')
        print('  cwd - show current directory')
        print('  exit - exit program')

    def cmd_exit(self, path: str):
        pass

    def loop(self):
        while(True):
            cwd = self._path_to_vault_str(self._cwd, no_prefix=True)
            cmd = input(f'Vault[{self._vault.uuid}]: {cwd} >> ')
            # TODO use argparse
            if cmd == 'exit':
                print('Bye bye!')
                break
            elif cmd == 'help':
                self.cmd_help()
            elif cmd == 'ls':
                self.cmd_ls()
            elif cmd.startswith('cd'):
                self.cmd_cd(cmd[3:])
            elif cmd.startswith('cwd'):
                self.cmd_cwd(cmd[4:])
            elif cmd.startswith('cat'):
                self.cmd_cat(cmd[4:])
            else:
                print('Unknown command')

class Cryptormator:
    ''' API to cryptomator vault '''

    def __init__(self, path, password):
        self._path: str = path
        self._vault: Vault = Vault(path).unlock(password)
        self._cli: Cli = Cli(self._vault)

        # unlock vault
        clearmem(password)
        if self._vault.unlocked:
            print('Vault opened')
            self._vault.index.dump_tree('clear_name')
        else:
            raise Exception('Vault could not be unlocked')
    
    def decrypt_file(self, src_path:str , dest_path: str, virtual: bool) -> None:
        ''' decrypts a file from the vault to a destination path, source can be virtual or cryptor path '''

        # translate virtual path to cryptor path
        if virtual:
           src_path = self._vault.locate(src_path) 
        
        # decrypt file
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(src_path,'rb') as src, open(dest_path, 'wb+') as dest:
            Common.decrypt_file(src, dest, self._vault.masterkey.primary, self._vault.cipher_combo)
    
    def decrypt(self, destination: str) -> bool:
        ''' decrypts the whole vault to a destination folwith open(dest_path, 'wb+') as destder '''
    
        os.makedirs(destination, exist_ok=True)
        
        #tree = self._vault.node_tree()
        
        pass
                
        
        

if __name__ == '__main__':
    password = '12345678'
    path = './test-vault/'
    
    ''' TODO features 
    
        - cryptomator-inspect, see gocryptfs-inspect

        - all features in cli mode => argparse selected ones route to cli

        - decrypt whole vault
        - decrypt file by 3 paths
        - extract masterkey
        - caclulate recovery phrase
    '''

    cm = Cryptormator(path, password)
    cm._cli.loop()
    #v.cwd()
    #v.ls()
    #v.cd('cyz')
    
    lnk = './test-vault/d/6A/B6NSMISQZ3ADX4LWWDF3TBL4KOQX3F/OgMVyWDp0GKPu8dbrmrPKgQXeuDKeLydKWBomZGU.c9r'
    txt = './test-vault/d/4A/IFYXYCOYCVJBJUYLK7WW3A6PG3JOS3/8vK4maKhH4VUu4wGN2ei7dprHzawsbQzsRh1w6b5Ew==.c9r'
    virtual = 'colors/red/g'
    dest = './test_outputs/test1.txt'
    data = cm.decrypt_file(virtual, dest, True)
    
    dest = './test_outputs/decrypt-vault'
    result = cm.decrypt(dest)
    pass
    
    
