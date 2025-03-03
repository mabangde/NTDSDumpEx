/**
 *  The MIT License:
 *
 *  Copyright (c) 2010, 2013 Kevin Devine
 *
 *  Permission is hereby granted,  free of charge,  to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"),  to deal
 *  in the Software without restriction,  including without limitation the rights
 *  to use,  copy,  modify,  merge,  publish,  distribute,  sublicense,  and/or sell
 *  copies of the Software,  and to permit persons to whom the Software is
 *  furnished to do so,  subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS",  WITHOUT WARRANTY OF ANY KIND,  EXPRESS OR
 *  IMPLIED,  INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  DAMAGES OR OTHER
 *  LIABILITY,  WHETHER IN AN ACTION OF CONTRACT,  TORT OR OTHERWISE,  ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

#pragma once
#define _CRT_NONSTDC_NO_WARNINGS
#ifndef _NTDS_H_
#define _NTDS_H_

#define UNICODE
#define _CRT_SECURE_NO_WARNINGS
#define JET_VERSION 0x0501

#include <windows.h> 
#include <esent.h>
#include <Sddl.h>
#include <string>
#include <vector>
#include <algorithm>
#include <wincrypt.h>
#include "attributes.h"

#define NTDS_PAGE_SIZE 8192

#define SAM_DOMAIN_OBJECT             0x00000000
#define SAM_GROUP_OBJECT             0x10000000
#define SAM_NON_SECURITY_GROUP_OBJECT    0x10000001
#define SAM_ALIAS_OBJECT             0x20000000
#define SAM_NON_SECURITY_ALIAS_OBJECT    0x20000001
#define SAM_USER_OBJECT                  0x30000000
#define SAM_MACHINE_ACCOUNT              0x30000001
#define SAM_TRUST_ACCOUNT                0x30000002
#define SAM_APP_BASIC_GROUP           0x40000000
#define SAM_APP_QUERY_GROUP           0x40000001
#define SAM_ACCOUNT_TYPE_MAX          0x7fffffff

 // 添加明文密码支持
#define PRIMARY_CLEARTEXT L"Primary:CLEARTEXT"

typedef enum {
    ADS_UF_SCRIPT = 1,        // 0x1
    ADS_UF_ACCOUNTDISABLE = 2,        // 0x2
    ADS_UF_HOMEDIR_REQUIRED = 8,        // 0x8
    ADS_UF_LOCKOUT = 16,       // 0x10
    ADS_UF_PASSWD_NOTREQD = 32,       // 0x20
    ADS_UF_PASSWD_CANT_CHANGE = 64,       // 0x40
    ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,      // 0x80
    ADS_UF_TEMP_DUPLICATE_ACCOUNT = 256,      // 0x100
    ADS_UF_NORMAL_ACCOUNT = 512,      // 0x200
    ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 2048,     // 0x800
    ADS_UF_WORKSTATION_TRUST_ACCOUNT = 4096,     // 0x1000
    ADS_UF_SERVER_TRUST_ACCOUNT = 8192,     // 0x2000
    ADS_UF_DONT_EXPIRE_PASSWD = 65536,    // 0x10000  
    ADS_UF_MNS_LOGON_ACCOUNT = 131072,   // 0x20000
    ADS_UF_SMARTCARD_REQUIRED = 262144,   // 0x40000
    ADS_UF_TRUSTED_FOR_DELEGATION = 524288,   // 0x80000
    ADS_UF_NOT_DELEGATED = 1048576,  // 0x100000
    ADS_UF_USE_DES_KEY_ONLY = 2097152,  // 0x200000
    ADS_UF_DONT_REQUIRE_PREAUTH = 4194304,  // 0x400000
    ADS_UF_PASSWORD_EXPIRED = 8388608,  // 0x800000
    ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216 // 0x1000000
} ADS_USER_FLAG_ENUM;

// 首先定义所有基本类型和常量
#define SYSTEM_KEY_LEN 16
#define LM_HASH_LEN 16
#define NT_HASH_LEN 16
#define PEK_SALT_LEN  16
#define PEK_AUTH_LEN  16
#define PEK_VALUE_LEN 16
#define PEK_SALT_ROUNDS 1000
#define PEK_REVISION_1 1
#define PEK_REVISION_2 2
#define SECRET_CRYPT_TYPE_RC4 0x11
#define SECRET_CRYPT_TYPE_AES 0x13


#define ATTR_USER_NAME               "sAMAccountName"
#define ATTR_USER_SID               "objectSid"
#define ATTR_NT_HASH                "unicodePwd"
#define ATTR_LM_HASH                "dBCSPwd"
#define ATTR_NT_HISTORY             "ntPwdHistory"
#define ATTR_LM_HISTORY             "lmPwdHistory"
#define ATTR_SUPPLEMENTAL_CREDS     "supplementalCredentials"



#define USER_PROPERTIES_SIGNATURE 'P'

// 然后按照依赖顺序定义结构体
typedef struct _PEK_HDR {
    DWORD dwVersion;
    DWORD dwFlag;
    BYTE bSalt[PEK_SALT_LEN];
} PEK_HDR, * PPEK_HDR;

typedef struct _PEK_DATA_ENTRY {
    DWORD dwIndex;
    BYTE bKey[PEK_VALUE_LEN];
} PEK_DATA_ENTRY, * PPEK_DATA_ENTRY;

typedef struct _PEK_DATA {
    BYTE bAuth[PEK_AUTH_LEN];
    FILETIME ftModified;
    DWORD dwCurrentIndex;
    DWORD dwTotalKeys;
    PEK_DATA_ENTRY entries[1];
} PEK_DATA, * PPEK_DATA;



typedef struct _PEK_LIST {
    PEK_HDR Hdr;
    PEK_DATA Data;
} PEK_LIST, * PPEK_LIST;

typedef struct _SECRET_DATA {
    WORD wType;
    WORD wUnknown;
    DWORD dwPEKIndex;
    BYTE bSalt[PEK_SALT_LEN];
    BYTE pbData[1];  // 变长数组
} SECRET_DATA, * PSECRET_DATA;

typedef struct _AES128_KEY_BLOB {
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE bKey[16];
} AES128_KEY_BLOB, * PAES128_KEY_BLOB;





// 定义属性ID结构
typedef struct _NTDS_ATTR_IDS {
    ULONG userNameId;
    ULONG userSidId;
    ULONG ntHashId;
    ULONG lmHashId;
    ULONG ntHistoryId;
    ULONG lmHistoryId;
    ULONG suppCredsId;
} NTDS_ATTR_IDS, * PNTDS_ATTR_IDS;


#pragma pack(push, 1) 
typedef struct _USER_PROPERTY {
    USHORT NameLength;
    USHORT ValueLength;
    USHORT Reserved;
    wchar_t PropertyName[ANYSIZE_ARRAY];
    // PropertyValue in HEX !
} USER_PROPERTY, * PUSER_PROPERTY;

typedef struct _USER_PROPERTIES {
    DWORD Reserved1;
    DWORD Length;
    USHORT Reserved2;
    USHORT Reserved3;
    BYTE Reserved4[96];
    wchar_t PropertySignature;    // 'P'
    USHORT PropertyCount;
    USER_PROPERTY UserProperties[ANYSIZE_ARRAY];
} USER_PROPERTIES, * PUSER_PROPERTIES;
#pragma pack(pop)

// 如果需要这些结构，也可以添加
typedef struct _SUPP_CRED {
    DWORD Signature;      // 'DES\0'
    DWORD CredentialCount;
    DWORD Reserved;
    struct {
        DWORD Offset;
        DWORD Size;
    } Credentials[ANYSIZE_ARRAY];
} SUPPCRED, * PSUPPCRED;

typedef struct _CRED_ENTRY {
    WCHAR Type[17];      // "Primary:CLEARTEXT"
    DWORD Size;
    WCHAR Data[ANYSIZE_ARRAY];
} CRED_ENTRY, * PCRED_ENTRY;


typedef struct _COLUMN_INFO {
    char name[JET_cbNameMost + 1];
    ULONG uColumnId;
    ULONG uAttrId;
} COLUMN_INFO, * PCOLUMN_INFO;




// 声明 PekListAuthenticator
extern const BYTE PekListAuthenticator[PEK_AUTH_LEN];

#ifdef DEBUG
#define dprintf printf
#else
#define dprintf
#endif

class NTDS {
    private:
        JET_INSTANCE instance;
        JET_SESID sesId;
        JET_DBID dbId;
        JET_TABLEID tableId;
        JET_ERR err;
        DWORD dwError;
        std::wstring dbName;
        BOOL bPrintSize;
        PPEK_LIST pekList;
        std::vector<COLUMN_INFO> columns;
        FILE* m_outFile;
        BOOL m_hasHistory;
        BOOL m_hasMachines;
        BOOL m_hasProfile;
        BOOL m_hasClearText;

        // 私有成员函数
        BOOL EnumColumns(VOID);
        ULONG GetColumnId(DWORD);
        BOOL IsAccountInactive(DWORD);
        BOOL IsAccountMachine(DWORD);
        DWORD GetColumnData(ULONG, PVOID, DWORD);
        VOID DumpHash(DWORD, PBYTE, DWORD, FILE*, char);
        VOID DisplayDecrypted(DWORD, PBYTE, FILE*, char);
        BOOL PEKDecryptSecretDataBlock(LPBYTE pbData, DWORD dwSize);
        BOOL EncryptDecryptWithKey(PBYTE, DWORD, PBYTE, DWORD, DWORD, PBYTE, DWORD);
        BOOL DecryptAes(PBYTE, DWORD, PBYTE, DWORD, PBYTE, DWORD);
        VOID ProcessHistoryHashes(const wchar_t* samName, DWORD rid,
            ULONG lmHistoryId, ULONG ntHistoryId,
            FILE* out, char fmt, DWORD* pHistoryCount);


public:
    NTDS();
    ~NTDS();

    // 基本操作函数
    BOOL Load(char*);
    BOOL UnLoad(VOID);
    BOOL GetPEKey(PBYTE, PBYTE);
    BOOL GetHashes(char, BOOL, BOOL, BOOL, BOOL, FILE*, DWORD*, DWORD*, DWORD*, DWORD*);
    std::string GetError(VOID);

    // 配置函数
    void SetDumpOptions(BOOL history, BOOL machines, BOOL profile, BOOL cleartext);
    void SetOutputFile(FILE* out);
    FILE* GetOutputFile();
    void SetClearTextOption(BOOL cleartext);

    // 密码相关函数
    std::string ParseSupplementalCredentials(PBYTE data, DWORD size, const wchar_t* userName);
    static int myIsSpace(int c); // 添加这一行
    void LogError(const char* operation, JET_ERR error);
};

#endif 