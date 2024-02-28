def set_payloads(li):
    PayloadStorage.payloads = li


def add_payload(item):
    PayloadStorage.payloads.append(item)


def get_payloads():
    return PayloadStorage.payloads


class PayloadStorage:
    payloads = []

################################
# Payload Class
################################
class Payload:
    # status_code values
    status_success  = 0
    status_hardfault= 1
    status_panic    = 2
    status_stuck    = 3
    status_timeout  = 4
    status_other    = 5

    # result_type values
    retype_void     = 0
    retype_uint     = 1
    retype_none     = 2

    def __init__(self):
        self.len = 0
        self.syscalls = []
        self.syscall_result_type = []
        self.syscall_results =[]
        self.status_code = None
        self.timestamp = None

        # auxiliary
        self.panic_code = None
        self.valid = False
        self.index = None
        self.covs_str = None
        self.sigs_str = None
        self.final_func = None
    # just for debugging
    def __str__(self):
        return     f'index: {self.index}\n' \
                   f'len: {self.len}\n' \
                   f'syscalls: {self.syscalls}\n' \
                   f'syscall_result_type: {self.syscall_result_type}\n' \
                   f'syscall_results: {self.syscall_results}\n' \
                   f'status_code: {self.status_code}\n' \
                   f'panic_code: {self.panic_code}\n' \
                   f'timestamp : {self.timestamp}'

    def add_func(self,log_line:str):
        _list = log_line.split()
        self.final_func = ' '.join(_list[1:])
        if _list[1].startswith('TA'):
            if 'return' in log_line:
                self.len += 1 
            return
        elif _list[1].startswith('TEE'):
            self.syscalls.append(_list[1])
            if 'return' in log_line:
                self.valid = True 
                self.len += 1 
                self.syscall_results.append(_list[-1])
                if _list[-1].startswith('0x'):
                    self.syscall_result_type.append(Payload.retype_uint)
                elif _list[-1] == 'void':
                    self.syscall_result_type.append(Payload.retype_void)
            elif 'invoke' in log_line:
                self.valid = True
                self.syscall_results.append(None)
                self.syscall_result_type.append(Payload.retype_none)

class StatePayload:
    def __init__(self):
        self.len = 0
        self.syscalls = []
        self.syscalls_states = []
        self.syscalls_sigs = []
        self.syscalls_covs = []
        self.index = None
    def __str__(self):
        return      f'len： {self.len}\n' \
                    f'syscalls: {self.syscalls}\n' \
                    f'syscalls_states: {self.syscalls_states}\n' \
                    f'syscalls_sigs: {self.syscalls_sigs}\n' \
                    f'syscalls_covs: {self.syscalls_covs}\n'


class Specification:
    algorithm_identifiers = {
        0:{
            'TEE_ALG_AES_CBC_NOPAD': 0x10000110,
            'TEE_ALG_AES_CCM': 0x40000710,
            'TEE_ALG_AES_CTR': 0x10000210,
            'TEE_ALG_AES_CTS': 0x10000310,
            'TEE_ALG_AES_ECB_NOPAD': 0x10000010,
            'TEE_ALG_AES_GCM': 0x40000810,
            'TEE_ALG_AES_XTS': 0x10000410,
        },
        1:{
            'TEE_ALG_DES_CBC_NOPAD': 0x10000111,
            'TEE_ALG_DES_ECB_NOPAD': 0x10000011,
        },
        2:{
            'TEE_ALG_DES3_CBC_NOPAD': 0x10000113,
            'TEE_ALG_DES3_ECB_NOPAD': 0x10000013,
        },
        3:{
            'TEE_ALG_SM4_CBC_NOPAD': 0x10000114,
            'TEE_ALG_SM4_CBC_PKCS5': 0x10000115,
            'TEE_ALG_SM4_CTR': 0x10000214,
            'TEE_ALG_SM4_ECB_NOPAD': 0x10000014,
            'TEE_ALG_SM4_ECB_PKCS5': 0x10000015,
        },
        4:{
            'TEE_ALG_RSA_NOPAD': 0x60000030,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1': 0x60210230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224': 0x60310230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256': 0x60410230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384': 0x60510230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512': 0x60610230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_224': 0x60810230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_256': 0x60910230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_384': 0x60A10230,
            'TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_512': 0x60B10230,
            'TEE_ALG_RSAES_PKCS1_V1_5': 0x60000130,
        },
        5:{
            'TEE_ALG_SM2_PKE': 0x80000046,
        },
        6:{
            'TEE_ALG_AES_CBC_MAC_NOPAD': 0x30000110,
            'TEE_ALG_AES_CBC_MAC_PKCS5': 0x30000510,
            'TEE_ALG_AES_CMAC': 0x30000610,
        },
        7:{
            'TEE_ALG_DES_CBC_MAC_NOPAD': 0x30000111,
            'TEE_ALG_DES_CBC_MAC_PKCS5': 0x30000511,
        },
        8:{
            'TEE_ALG_DES3_CBC_MAC_NOPAD': 0x30000113,
            'TEE_ALG_DES3_CBC_MAC_PKCS5': 0x30000513,
        },
        9:{
            'TEE_ALG_HMAC_MD5': 0x30000001,
        },
        10:{
            'TEE_ALG_HMAC_SHA1': 0x30000002,
        },
        11:{
            'TEE_ALG_HMAC_SHA224': 0x30000003,
        },
        12:{
            'TEE_ALG_HMAC_SHA256': 0x30000004,
        },
        13:{
            'TEE_ALG_HMAC_SHA384': 0x30000005,
        },
        14:{
            'TEE_ALG_HMAC_SHA512': 0x30000006,
        },
        15:{
            'TEE_ALG_HMAC_SHA3_224': 0x30000008,
        },
        16:{
            'TEE_ALG_HMAC_SHA3_256': 0x30000009,
        },
        17:{
            'TEE_ALG_HMAC_SHA3_384': 0x3000000A,
        },
        18:{
            'TEE_ALG_HMAC_SHA3_512': 0x3000000B,
        },
        19:{
            'TEE_ALG_HMAC_SM3': 0x30000007,
        },
        20:{
            'TEE_ALG_MD5': 0x50000001,
            'TEE_ALG_SHA1': 0x50000002,
            'TEE_ALG_SHA224': 0x50000003,
            'TEE_ALG_SHA256': 0x50000004,
            'TEE_ALG_SHA384': 0x50000005,
            'TEE_ALG_SHA3_224': 0x50000008,
            'TEE_ALG_SHA3_256': 0x50000009,
            'TEE_ALG_SHA3_384': 0x5000000A,
            'TEE_ALG_SHA3_512': 0x5000000B,
            'TEE_ALG_SHAKE128': 0x50000101,
            'TEE_ALG_SHAKE256': 0x50000102,
            'TEE_ALG_SM3': 0x50000007,
        },
        21:{
            'TEE_ALG_DSA_SHA1': 0x70002131,
            'TEE_ALG_DSA_SHA224': 0x70003131,
            'TEE_ALG_DSA_SHA256': 0x70004131,
            'TEE_ALG_DSA_SHA3_224': 0x70008131,
            'TEE_ALG_DSA_SHA3_256': 0x70009131,
            'TEE_ALG_DSA_SHA3_384': 0x7000A131,
            'TEE_ALG_DSA_SHA3_512': 0x7000B131,
        },
        22:{
            'TEE_ALG_ECDSA_SHA1': 0x70001042,
            'TEE_ALG_ECDSA_SHA224': 0x70002042,
            'TEE_ALG_ECDSA_SHA256': 0x70003042,
            'TEE_ALG_ECDSA_SHA384': 0x70004042,
            'TEE_ALG_ECDSA_SHA512': 0x70005042,
            'TEE_ALG_ECDSA_SHA3_224': 0x70006042,
            'TEE_ALG_ECDSA_SHA3_256': 0x70007042,
            'TEE_ALG_ECDSA_SHA3_384': 0x70008042,
            'TEE_ALG_ECDSA_SHA3_512': 0x70009042,
        },
        23:{
            'TEE_ALG_ED25519': 0x70006043,
        },
        24:{
            'TEE_ALG_ED448': 0x70006044,
        },
        25:{
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1': 0x70212930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224': 0x70313930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256': 0x70414930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384': 0x70515930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512': 0x70616930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_224': 0x70818930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_256': 0x70919930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_384': 0x70A1A930,
            'TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_512': 0x70B1B930,
            'TEE_ALG_RSASSA_PKCS1_V1_5_MD5': 0x70001830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA1': 0x70002830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA224': 0x70003830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA256': 0x70004830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA384': 0x70005830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA512': 0x70006830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_224': 0x70008830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_256': 0x70009830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_384': 0x7000A830,
            'TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_512': 0x7000B830,
        },
        26:{
            'TEE_ALG_SM2_DSA_SM3': 0x70006045,
        },
        27:{
            'TEE_ALG_DH_DERIVE_SHARED_SECRET': 0x80000032,
        },
        28:{
            'TEE_ALG_ECDH_DERIVE_SHARED_SECRET': 0x80000042,
        },
        29:{
            'TEE_ALG_X25519': 0x80000044,
        },
        30:{
            'TEE_ALG_X448': 0x80000045,
        },
        31:{
            'TEE_ALG_SM2_KEP': 0x60000045,
        },
        32:{
            'TEE_ALG_HKDF': 0x80000047,
        },
    }
    object_types = {
        0:{'TEE_TYPE_AES' :0xA0000010,},
        1:{'TEE_TYPE_DES' :0xA0000011,},
        2:{'TEE_TYPE_DES3' :0xA0000013,},
        3:{'TEE_TYPE_SM4':0xA0000014},
        4:{'TEE_TYPE_RSA_KEYPAIR' :0xA1000030, 'TEE_TYPE_RSA_PUBLIC_KEY' :0xA0000030,},
        5:{'TEE_TYPE_SM2_PKE_KEYPAIR':0xA1000047,'TEE_TYPE_SM2_PKE_PUBLIC_KEY':0xA0000047},
        6:{'TEE_TYPE_AES' :0xA0000010,},
        7:{'TEE_TYPE_DES' :0xA0000011,},
        8:{'TEE_TYPE_DES3': 0xA0000013,},
        9:{'TEE_TYPE_HMAC_MD5' :0xA0000001,},
        10:{'TEE_TYPE_HMAC_SHA1' :0xA0000002,},
        11:{'TEE_TYPE_HMAC_SHA224' :0xA0000003,},
        12:{'TEE_TYPE_HMAC_SHA256' :0xA0000004,},
        13:{'TEE_TYPE_HMAC_SHA384' :0xA0000005,},
        14:{'TEE_TYPE_HMAC_SHA512' :0xA000f0006,},
        15:{'TEE_TYPE_HMAC_SHA3_224':0xA0000008},
        16:{'TEE_TYPE_HMAC_SHA3_256':0xA0000009},
        17:{'TEE_TYPE_HMAC_SHA3_384':0xA000000A},
        18:{'TEE_TYPE_HMAC_SHA3_512':0xA000000B},
        19:{'TEE_TYPE_HMAC_SM3':0xA0000007},
        20:{},
        21:{'TEE_TYPE_DSA_KEYPAIR' :0xA1000031, 'TEE_TYPE_DSA_PUBLIC_KEY' :0xA0000031,},
        22:{'TEE_TYPE_ECDSA_KEYPAIR' :0xA1000041, 'TEE_TYPE_ECDSA_PUBLIC_KEY' :0xA0000041,},
        23:{'TEE_TYPE_ED25519_KEYPAIR':0xA1000043,'TEE_TYPE_ED25519_PUBLIC_KEY':0xA0000043},
        24:{'TEE_TYPE_ED448_KEYPAIR':0xA1000048,'TEE_TYPE_ED448_PUBLIC_KEY':0xA0000048},
        25:{'TEE_TYPE_RSA_KEYPAIR' :0xA1000030, 'TEE_TYPE_RSA_PUBLIC_KEY' :0xA0000030,},
        26:{'TEE_TYPE_SM2_DSA_KEYPAIR':0xA1000045,'TEE_TYPE_SM2_DSA_PUBLIC_KEY':0xA0000045},
        27:{'TEE_TYPE_DH_KEYPAIR' :0xA1000032,},
        28:{'TEE_TYPE_ECDH_KEYPAIR' :0xA1000042,},
        29:{'TEE_TYPE_X25519_KEYPAIR':0xA1000044},
        30:{'TEE_TYPE_X448_KEYPAIR':0xA1000049},
        31:{'TEE_TYPE_SM2_KEP_KEYPAIR':0xA1000046},
        32:{'TEE_TYPE_HKDF':0xA000004A},
    },
    TEE_OperationMode = {
        0:{'TEE_MODE_ENCRYPT' : 0,'TEE_MODE_DECRYPT' : 1,},
        1:{'TEE_MODE_ENCRYPT' : 0,'TEE_MODE_DECRYPT' : 1,},
        2:{'TEE_MODE_ENCRYPT' : 0,'TEE_MODE_DECRYPT' : 1,},
        3:{'TEE_MODE_ENCRYPT' : 0,'TEE_MODE_DECRYPT' : 1,},
        4:{'TEE_MODE_ENCRYPT' : 0,'TEE_MODE_DECRYPT' : 1,},
        5:{'TEE_MODE_ENCRYPT' : 0,'TEE_MODE_DECRYPT' : 1,},
        6:{'TEE_MODE_MAC' : 4,},
        7:{'TEE_MODE_MAC' : 4,},
        8:{'TEE_MODE_MAC' : 4,},
        9:{'TEE_MODE_MAC' : 4,},
        10:{'TEE_MODE_MAC' : 4,},
        11:{'TEE_MODE_MAC' : 4,},
        12:{'TEE_MODE_MAC' : 4,},
        13:{'TEE_MODE_MAC' : 4,},
        14:{'TEE_MODE_MAC' : 4,},
        15:{'TEE_MODE_MAC' : 4,},
        16:{'TEE_MODE_MAC' : 4,},
        17:{'TEE_MODE_MAC' : 4,},
        18:{'TEE_MODE_MAC' : 4,},
        19:{'TEE_MODE_MAC' : 4,},
        20:{'TEE_MODE_DIGEST' :5,},
        21:{'TEE_MODE_SIGN' : 2, 'TEE_MODE_VERIFY' :3,},
        22:{'TEE_MODE_SIGN' : 2, 'TEE_MODE_VERIFY' :3,},
        23:{'TEE_MODE_SIGN' : 2, 'TEE_MODE_VERIFY' :3,},
        24:{'TEE_MODE_SIGN' : 2, 'TEE_MODE_VERIFY' :3,},
        25:{'TEE_MODE_SIGN' : 2, 'TEE_MODE_VERIFY' :3,},
        26:{'TEE_MODE_SIGN' : 2, 'TEE_MODE_VERIFY' :3,},
        27:{'TEE_MODE_DERIVE' : 6,},
        28:{'TEE_MODE_DERIVE' : 6,},
        29:{'TEE_MODE_DERIVE' : 6,},
        30:{'TEE_MODE_DERIVE' : 6,},
        31:{'TEE_MODE_DERIVE' : 6,},
        32:{'TEE_MODE_DERIVE' : 6,},
    }
    operation_attributes = {
        'TEE_ATTR_SECRET_VALUE' :               0xC0000000,
        'TEE_ATTR_RSA_MODULUS' :                0xD0000130,
        'TEE_ATTR_RSA_PUBLIC_EXPONENT' :        0xD0000230,
        'TEE_ATTR_RSA_PRIVATE_EXPONENT' :       0xC0000330,
        'TEE_ATTR_RSA_PRIME1' :                 0xC0000430,
        'TEE_ATTR_RSA_PRIME2' :                 0xC0000530,
        'TEE_ATTR_RSA_EXPONENT1' :              0xC0000630,
        'TEE_ATTR_RSA_EXPONENT2' :              0xC0000730,
        'TEE_ATTR_RSA_COEFFICIENT' :            0xC0000830,
        'TEE_ATTR_DSA_PRIME' :                  0xD0001031,
        'TEE_ATTR_DSA_SUBPRIME' :               0xD0001131,
        'TEE_ATTR_DSA_BASE' :                   0xD0001231,
        'TEE_ATTR_DSA_PUBLIC_VALUE' :           0xD0000131,
        'TEE_ATTR_DSA_PRIVATE_VALUE' :          0xC0000231,
        'TEE_ATTR_DH_PRIME' :                   0xD0001032,
        'TEE_ATTR_DH_SUBPRIME' :                0xD0001132,
        'TEE_ATTR_DH_BASE' :                    0xD0001232,
        'TEE_ATTR_DH_X_BITS' :                  0xF0001332,
        'TEE_ATTR_DH_PUBLIC_VALUE' :            0xD0000132,
        'TEE_ATTR_DH_PRIVATE_VALUE' :           0xC0000232,
        'TEE_ATTR_RSA_OAEP_LABEL' :             0xD0000930,
        'TEE_ATTR_RSA_PSS_SALT_LENGTH' :        0xF0000A30,
        'TEE_ATTR_ECC_PUBLIC_VALUE_X' :         0xD0000141,
        'TEE_ATTR_ECC_PUBLIC_VALUE_Y' :         0xD0000241,
        'TEE_ATTR_ECC_PRIVATE_VALUE' :          0xC0000341,
        'TEE_ATTR_ECC_CURVE' :                  0xF0000441,
        'TEE_ATTR_BIT_PROTECTED' :              1 << 28,
        'TEE_ATTR_BIT_VALUE' :                  1 << 29,
    }

    