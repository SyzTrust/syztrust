TEE_Return_Code={
    "TEE_SUCCESS" : "0x00000000",
    "TEE_ERROR_CORRUPT_OBJECT" : "0xF0100001",
    "TEE_ERROR_CORRUPT_OBJECT_2" : "0xF0100002",
    "TEE_ERROR_STORAGE_NOT_AVAILABLE" : "0xF0100003",
    "TEE_ERROR_STORAGE_NOT_AVAILABLE_2" : "0xF0100004",
    "TEE_ERROR_UNSUPPORTED_VERSION" : "0xF0100005",
    "TEE_ERROR_CIPHERTEXT_INVALID" : "0xF0100006",
    "TEE_ERROR_GENERIC" : "0xFFFF0000",
    "TEE_ERROR_ACCESS_DENIED" : "0xFFFF0001",
    "TEE_ERROR_CANCEL" : "0xFFFF0002",
    "TEE_ERROR_ACCESS_CONFLICT" : "0xFFFF0003",
    "TEE_ERROR_EXCESS_DATA" : "0xFFFF0004",
    "TEE_ERROR_BAD_FORMAT" : "0xFFFF0005",
    "TEE_ERROR_BAD_PARAMETERS" : "0xFFFF0006",
    "TEE_ERROR_BAD_STATE" : "0xFFFF0007",
    "TEE_ERROR_ITEM_NOT_FOUND" : "0xFFFF0008",
    "TEE_ERROR_NOT_IMPLEMENTED" : "0xFFFF0009",
    "TEE_ERROR_NOT_SUPPORTED" : "0xFFFF000A",
    "TEE_ERROR_NO_DATA" : "0xFFFF000B",
    "TEE_ERROR_OUT_OF_MEMORY" : "0xFFFF000C",
    "TEE_ERROR_BUSY" : "0xFFFF000D",
    "TEE_ERROR_COMMUNICATION" : "0xFFFF000E",
    "TEE_ERROR_SECURITY" : "0xFFFF000F",
    "TEE_ERROR_SHORT_BUFFER" : "0xFFFF0010",
    "TEE_ERROR_EXTERNAL_CANCEL" : "0xFFFF0011",
    "TEE_ERROR_TIMEOUT" : "0xFFFF3001",
    "TEE_ERROR_OVERFLOW" : "0xFFFF300F",
    "TEE_ERROR_TARGET_DEAD" : "0xFFFF3024",
    "TEE_ERROR_STORAGE_NO_SPACE" : "0xFFFF3041",
    "TEE_ERROR_MAC_INVALID" : "0xFFFF3071",
    "TEE_ERROR_SIGNATURE_INVALID" : "0xFFFF3072",
    "TEE_ERROR_TIME_NOT_SET" : "0xFFFF5000",
    "TEE_ERROR_TIME_NEEDS_RESET": "0xFFFF5001",
    "TEE_NO_RETURN_CODE": "void"
}


TEE_Syscall_Void = ["TEE_FreePropertyEnumerator", "TEE_StartPropertyEnumerator",
    "TEE_ResetPropertyEnumerator", "TEE_Panic",
    "TEE_CloseTASession", "TEE_SetInstanceData",
    "TEE_Free","TEE_MemMove",
    "TEE_CloseObject", "TEE_FreeTransientObject",
    "TEE_ResetTransientObject", "TEE_InitRefAttribute",
    "TEE_InitValueAttribute", "TEE_FreePersistentObjectEnumerator",
    "TEE_ResetPersistentObjectEnumerator", "TEE_FreeOperation",
    "TEE_GetOperationInfo", "TEE_ResetOperation",
    "TEE_CopyOperation", "TEE_DigestUpdate",
    "TEE_CipherInit", "TEE_MACInit",
    "TEE_MACUpdate", "TEE_AEUpdateAAD",
    "TEE_DeriveKey", "TEE_GenerateRandom",
    "TEE_GetSystemTime", "TEE_GetREETime",
    "TEE_BigIntInit", "TEE_BigIntInitFMM",
    "TEE_BigIntConvertFromS32", "TEE_BigIntShiftRight",
    "TEE_BigIntAdd", "TEE_BigIntSub",
    "TEE_BigIntNeg", "TEE_BigIntMul",
    "TEE_BigIntSquare", "TEE_BigIntDiv",
    "TEE_BigIntMod", "TEE_BigIntAddMod",
    "TEE_BigIntSubMod", "TEE_BigIntMulMod",
    "TEE_BigIntSquareMod", "TEE_BigIntInvMod",
    "TEE_BigIntComputeExtendedGcd", "TEE_BigIntConvertToFMM",
    "TEE_BigIntConvertFromFMM", "TEE_BigIntComputeFMM",

    # these 4 functions returns void* ; does not care actual address ; regard them as void.
    "TEE_Malloc", "TEE_Realloc", "TEE_MemFill", "TEE_GetInstanceData",

]

TEE_Syscall_Void_Deprecated = [
    "TEE_GetObjectInfo", "TEE_RestrictObjectUsage",
    "TEE_CopyObjectAttributes", "TEE_CloseAndDeletePersistentObject",
    "TEE_BigIntInitFMMContext",
]

TEE_Syscall_Ptr = [
    "TEE_Malloc","TEE_Realloc","TEE_MemFill","TEE_GetInstanceData",
]

TEE_Syscall_Uint32 = [
    "TEE_AllocateOperation","TEE_GetOperationInfoMultiple","TEE_SetOperationKey",
    "TEE_SetOperationKey2","TEE_DigestDoFinal","TEE_CipherUpdate","TEE_CipherDoFinal",
    "TEE_MACComputeFinal","TEE_MACCompareFinal","TEE_AEInit","TEE_AEUpdate","TEE_AEEncryptFinal",
    "TEE_AEDecryptFinal","TEE_AsymmetricEncrypt","TEE_AsymmetricDecrypt","TEE_AsymmetricSignDigest",
    "TEE_AsymmetricVerifyDigest",

    "TEE_OpenTASession","TEE_InvokeTACommand"
]

TEE_Syscall_Bool = [
    "TEE_GetCancellationFlag","TEE_UnmaskCancellation","TEE_MaskCancellation","TEE_BigIntGetBit",
    "TEE_BigIntRelativePrime",
]