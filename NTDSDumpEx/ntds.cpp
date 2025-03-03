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

#include "ntds.h"
#include <memory>
#include <stdexcept>

#pragma comment(lib, "esent.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

/**********************************************************
 *
 *  + Set page size
 *  + Set recovery off
 *  + Create instance
 *  + Create session
 *
 **********************************************************/
class CryptContext {
	HCRYPTPROV hProv;
public:
	CryptContext() : hProv(NULL) {
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
			throw std::runtime_error("Failed to acquire crypt context");
		}
	}

	~CryptContext() {
		if (hProv) CryptReleaseContext(hProv, 0);
	}

	operator HCRYPTPROV() const { return hProv; }
};


NTDS::NTDS() :
	instance(NULL),
	sesId(NULL),
	dbId(NULL),
	tableId(NULL),
	err(0),
	dwError(0),
	bPrintSize(FALSE),
	pekList(NULL),
	m_outFile(NULL),
	m_hasHistory(FALSE),
	m_hasMachines(FALSE),
	m_hasProfile(FALSE),
	m_hasClearText(FALSE)
{
	// 初始化 JET 参数
	if (JetSetSystemParameter(&instance, JET_sesidNil,
		JET_paramDatabasePageSize, NTDS_PAGE_SIZE, NULL) == JET_errSuccess) {

		if (JetSetSystemParameter(&instance, JET_sesidNil,
			JET_paramRecovery, NULL, (JET_PCSTR)"Off") == JET_errSuccess) {

			if (JetCreateInstance(&instance, (JET_PCSTR)"ntdsdump_0_3") == JET_errSuccess) {

				if (JetInit(&instance) == JET_errSuccess) {
					JetBeginSession(instance, &sesId, NULL, NULL);
				}
			}
		}
	}
}

int NTDS::myIsSpace(int c) {
	return c == '\n'
		|| c == '\r'
		|| c == '\t'
		|| c == '\v'
		|| c == '\f'
		|| c == ':';  // for john format
}


void NTDS::SetOutputFile(FILE* outFile) {
	m_outFile = outFile; // 确保这一行存在
}


void NTDS::LogError(const char* operation, JET_ERR error) {
	printf("[-]Error in %s: JET_err = %d\n", operation, error);
	switch (error) {
	case JET_errDatabaseDirtyShutdown:
		printf("  Database is in dirty shutdown state. Run esentutl /r to recover.\n");
		break;
	case JET_errFileNotFound:
		printf("  Database file not found\n");
		break;
		// 添加其他错误处理...
	}
}


void NTDS::SetDumpOptions(BOOL hasHistory, BOOL hasMachines, BOOL hasProfile, BOOL hasClearText) {
	m_hasHistory = hasHistory;
	m_hasMachines = hasMachines;
	m_hasProfile = hasProfile;
	m_hasClearText = hasClearText;  // 确保这个赋值正确
}

/**********************************************************
 *
 *  + Close database
 *  + Detach database
 *  + End session
 *  + Terminate instance
 *
 **********************************************************/
NTDS::~NTDS() {

	if (dbId != NULL || sesId != NULL || instance != NULL || !dbName.empty()) {

		UnLoad();

		if (dbName.empty() && sesId != NULL) {
			// end session
			err = JetEndSession(sesId, 0);
			if (err == JET_errSuccess) {
				sesId = NULL;
			}
			else {
			}
		}
		if (sesId == NULL && instance != NULL) {
			// terminate instance
			err = JetTerm(instance);
			if (err == JET_errSuccess) {
				instance = NULL;
			}
			else {
			}
		}
	}
}

/**********************************************************
 *
 *  + Attach database
 *  + Open database
 *  + Enumerate columns
 *
 **********************************************************/
BOOL NTDS::Load(char* fname) {
	printf("[+]Loading database: %s\n", fname);

	if (!UnLoad()) {
		LogError("UnLoad", err);
		return FALSE;
	}

	if ((err = JetAttachDatabaseA(sesId, fname, JET_bitDbReadOnly)) != JET_errSuccess) {
		LogError("JetAttachDatabase", err);
		return FALSE;
	}

	// 转换数据库名称
	std::string database(fname);
	dbName = std::wstring(database.begin(), database.end());

	// 打开数据库
	wchar_t wsConnect[128] = { 0 };
	err = JetOpenDatabaseA(sesId, fname, NULL, &dbId, JET_bitDbReadOnly);
	if (err != JET_errSuccess) {
		printf("[-]Failed to open database: JET_err = %d\n", err);
		// 清理已附加的数据库
		JetDetachDatabaseA(sesId, fname);
		return FALSE;
	}

	printf("[+]Successfully opened database\n");

	// 枚举列
	if (!EnumColumns()) {
		printf("[-]Failed to enumerate columns\n");
		// 清理
		JetCloseDatabase(sesId, dbId, 0);
		JetDetachDatabaseA(sesId, fname);
		return FALSE;
	}

	printf("[+]Successfully enumerated columns\n");
	return TRUE;
}

/**********************************************************
 *
 *  + Close database
 *  + Detach database
 *
 **********************************************************/
BOOL NTDS::UnLoad(VOID) {

	// close database
	if (dbId != NULL) {
		err = JetCloseDatabase(sesId, dbId, 0);
		if (err == JET_errSuccess) {
			dbId = NULL;
		}
	}
	// detach from session
	if (dbId == NULL && !dbName.empty()) {
		std::string database(dbName.begin(), dbName.end());
		err = JetDetachDatabase(sesId, (JET_PCSTR)database.c_str());
		if (err == JET_errSuccess) {
			dbName.clear();
		}
	}
	// clear column list
	if (dbName.empty() && columns.size() != 0) {
		columns.clear();
	}
	return err == JET_errSuccess;
}

/**********************************************************
 *
 *  + Open MSysObjects
 *  + Enumerate columns
 *
 **********************************************************/
std::string NTDS::GetError(VOID) {
	char szError[256] = { 0 };
	sprintf_s(szError, "JET_err = %d", err);
	return std::string(szError);
}

/**********************************************************
 *
 *  + Open MSysObjects
 *  + Enumerate columns
 *
 *  We're only interested in attributes for ntds.dit
 *
 **********************************************************/
BOOL NTDS::EnumColumns(VOID) {
	JET_TABLEID tableId;
	JET_COLUMNLIST colList;

	// open MSysObjects table
	err = JetOpenTable(sesId, dbId, (JET_PCSTR)"MSysObjects", NULL, 0,
		JET_bitTableReadOnly | JET_bitTableSequential, &tableId);

	if (err != JET_errSuccess) {
		return FALSE;
	}

	// obtain list of columns
	colList.cbStruct = sizeof(colList);
	err = JetGetTableColumnInfo(sesId, tableId, NULL, &colList,
		sizeof(colList), JET_ColInfoListSortColumnid);

	if (err == JET_errSuccess) {
		err = JetMove(sesId, tableId, JET_MoveFirst, JET_bitNil);
		do {
			COLUMN_INFO info;
			memset(info.name, 0, sizeof(info.name));
			// get the column name
			err = JetRetrieveColumn(sesId, tableId, colList.columnidcolumnname,
				info.name, sizeof(info.name), NULL, JET_bitNil, NULL);

			if (err == JET_errSuccess) {
				// if this is an attribute
				if (info.name[0] == 'A'
					&& info.name[1] == 'T'
					&& info.name[2] == 'T') {
					err = JetRetrieveColumn(sesId, tableId, colList.columnidcoltyp,
						&info.uColumnId, sizeof(info.uColumnId), NULL, JET_bitNil, NULL);
					if (err == JET_errSuccess) {
						info.uAttrId = atol(&info.name[4]);
						columns.push_back(info);
					}
				}
			}

		} while ((err = JetMove(sesId, tableId, JET_MoveNext, JET_bitNil)) == JET_errSuccess);
	}

	err = JetCloseTable(sesId, tableId);
	return err == JET_errSuccess;
}


/**
 *
 *  Column names can change depending on state
 *  so it's unwise to hardcode the names
 *
 */
ULONG NTDS::GetColumnId(ULONG uAttrId) {
	//printf("[+]Looking for attribute ID: %lu\n", uAttrId);
	//printf("[+]Total columns in list: %zu\n", columns.size());

	ULONG Id = 0;
	for (size_t i = 0; i < columns.size(); i++) {
		//printf("[+]Checking column %zu: AttrId=%lu, ColumnId=%lu\n",i, columns[i].uAttrId, columns[i].uColumnId);
		if (uAttrId == columns[i].uAttrId) {
			Id = columns[i].uColumnId;
			//printf("[+]Found matching column ID: %lu\n", Id);
			break;
		}
	}

	if (Id == 0) {
		printf("[-]Failed to find column ID for attribute %lu\n", uAttrId);
	}
	return Id;
}

BOOL NTDS::EncryptDecryptWithKey(PBYTE pbKey, DWORD dwKeyLen,
	PBYTE pbSalt, DWORD dwSaltLen,
	DWORD dwSaltRounds,
	PBYTE pbData, DWORD dwDataLen) {
	try {
		CryptContext hProv;
		HCRYPTHASH hHash = NULL;
		HCRYPTKEY hKey = NULL;

		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
			throw std::runtime_error("Failed to create hash");
		}

		// 使用RAII模式管理HCRYPTHASH
		class HashGuard {
			HCRYPTHASH& hash;
		public:
			explicit HashGuard(HCRYPTHASH& h) : hash(h) {}
			~HashGuard() {
				if (hash) {
					CryptDestroyHash(hash);
					hash = NULL;
				}
			}
		};

		// 创建guard对象来管理hash
		HashGuard hashGuard(hHash);

		// first, the key
		if (!CryptHashData(hHash, pbKey, dwKeyLen, 0)) {
			throw std::runtime_error("Failed to hash key data");
		}

		// now the salt
		for (DWORD i = 0; i < dwSaltRounds; i++) {
			if (!CryptHashData(hHash, pbSalt, dwSaltLen, 0)) {
				throw std::runtime_error("Failed to hash salt data");
			}
		}

		// get an RC4 key
		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0x00800000, &hKey)) {
			throw std::runtime_error("Failed to derive key");
		}

		// 使用RAII模式管理HCRYPTKEY
		class KeyGuard {
			HCRYPTKEY& key;
		public:
			explicit KeyGuard(HCRYPTKEY& k) : key(k) {}
			~KeyGuard() {
				if (key) {
					CryptDestroyKey(key);
					key = NULL;
				}
			}
		};

		// 创建guard对象来管理key
		KeyGuard keyGuard(hKey);

		// decrypt or encrypt..RC4 is a stream cipher so it doesn't matter
		if (!CryptEncrypt(hKey, NULL, TRUE, 0, pbData, &dwDataLen, dwDataLen)) {
			throw std::runtime_error("Failed to encrypt/decrypt data");
		}

		return TRUE;
	}
	catch (const std::exception& e) {
		printf("[-]Encryption error: %s\n", e.what());
		return FALSE;
	}
}

BOOL NTDS::DecryptAes(PBYTE pbKey, DWORD dwKeyLen,
	PBYTE pbSalt, DWORD dwSaltLen,
	PBYTE pbData, DWORD dwDataLen) {
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	AES128_KEY_BLOB blob = { 0 };
	BOOL bResult = FALSE;
	DWORD d = dwDataLen;

	if (CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
		CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT)) {
		blob.hdr.bType = PLAINTEXTKEYBLOB;
		blob.hdr.bVersion = CUR_BLOB_VERSION;
		blob.hdr.reserved = 0;
		blob.hdr.aiKeyAlg = CALG_AES_128;
		blob.dwKeySize = 16;
		memcpy(blob.bKey, pbKey, 16);
		if (CryptImportKey(hProv, (PBYTE)&blob, sizeof(AES128_KEY_BLOB), 0, 0, &hKey) &&
			CryptSetKeyParam(hKey, KP_IV, pbSalt, 0)) {
			bResult = CryptDecrypt(hKey, 0, 0, 0, pbData, &d);
		}
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
	}
	return bResult;
}



const BYTE PekListAuthenticator[PEK_AUTH_LEN] =
{ 0x56, 0xD9, 0x81, 0x48, 0xEC, 0x91, 0xD1, 0x11,
  0x90, 0x5A, 0x00, 0xC0, 0x4F, 0xC2, 0xD4, 0xCF };

/**********************************************************
 *
 *  + Obtain Pek-List
 *  + Open datatable
 *  + Retrieve list and decrypt first key
 *
 **********************************************************/
BOOL NTDS::GetPEKey(PBYTE pbSysKey, PBYTE pbPEKey) {
	int pekId = GetColumnId(ATT_PEK_LIST);
	BOOL bResult = FALSE;

	// need column id at least
	if (pekId == 0) {
		return FALSE;
}

	// open the datatable
	JET_TABLEID tableId;
	err = JetOpenTable(sesId, dbId, (JET_PCSTR)"datatable", NULL, 0,
		JET_bitTableReadOnly | JET_bitTableSequential, &tableId);

	if (err != JET_errSuccess) {
		return FALSE;
	}

	// go to first
	err = JetMove(sesId, tableId, JET_MoveFirst, JET_bitNil);

	// while good read
	while (err == JET_errSuccess) {
		DWORD dwPekListSize = 0;
		err = JetRetrieveColumn(sesId, tableId, pekId,
			NULL, 0, &dwPekListSize, JET_bitNil, NULL);

		if (err == JET_wrnBufferTruncated) {
			if (pekList) {
				free(pekList);
				pekList = NULL;
			}
			pekList = (PPEK_LIST)malloc(dwPekListSize);
			if (!pekList) {
				JetCloseTable(sesId, tableId);
				return FALSE;
			}

			err = JetRetrieveColumn(sesId, tableId, pekId,
				pekList, dwPekListSize, &dwPekListSize, JET_bitNil, NULL);

			if (err == JET_errSuccess) {
				printf("[+]PEK Header Version: %d\n", pekList->Hdr.dwVersion);
				printf("[+]PEK Header Flag: %d\n", pekList->Hdr.dwFlag);
				printf("[+]PEK Salt: ");
				for (int i = 0; i < PEK_SALT_LEN; i++) {
					printf("%02X ", pekList->Hdr.bSalt[i]);
				}
				printf("\n");

				if (pekList->Hdr.dwFlag) {
					BOOL decryptSuccess = FALSE;
					if (pekList->Hdr.dwVersion == 2) {
						printf("[+]Using RC4 decryption\n");
						decryptSuccess = EncryptDecryptWithKey(pbSysKey, SYSTEM_KEY_LEN,
							pekList->Hdr.bSalt, PEK_SALT_LEN, PEK_SALT_ROUNDS,
							(PBYTE)&pekList->Data, dwPekListSize - sizeof(PEK_HDR));
					}
					else if (pekList->Hdr.dwVersion == 3) {
						printf("[+]Using AES decryption\n");
						decryptSuccess = DecryptAes(pbSysKey, SYSTEM_KEY_LEN,
							pekList->Hdr.bSalt, PEK_SALT_LEN,
							(PBYTE)&pekList->Data, dwPekListSize - sizeof(PEK_HDR));
					}

					if (decryptSuccess) {
						printf("[+]Auth data: ");
						for (int i = 0; i < PEK_AUTH_LEN; i++) {
							printf("%02X ", pekList->Data.bAuth[i]);
						}
						printf("\n");

						if (memcmp(pekList->Data.bAuth, PekListAuthenticator, PEK_AUTH_LEN) == 0) {
							printf("[+]PEK authentication successful\n");
							memcpy(pbPEKey, pekList->Data.entries[0].bKey, PEK_VALUE_LEN);
							bResult = TRUE;
							break;
						}
						else {
							printf("[-]PEK authentication failed\n");
						}
					}
				}
			}
		}
		err = JetMove(sesId, tableId, JET_MoveNext, JET_bitNil);
	}

	JetCloseTable(sesId, tableId);
	return bResult;
}


#define ROL32(a, n)(((a) << (n)) | (((a) & 0xffffffff) >> (32 - (n))))
#define ROR32(a, n)((((a) & 0xffffffff) >> (n)) | ((a) << (32 - (n))))

#ifdef BIGENDIAN
# define SWAP32(n) (n)
#else
# define SWAP32(n) \
	ROR32((((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8)), 16)
#endif

/**
 *
 *  Convert a string to DES key
 *
 */
void str2key(LPBYTE str, LPBYTE key) {
	DWORD x1, x2, r1, r2;
	PDWORD p1, p2, out = (PDWORD)key;
	int i;

	p1 = (PDWORD)&str[0];
	p2 = (PDWORD)&str[3];

	x1 = SWAP32(p1[0]);
	x2 = ROL32(SWAP32(p2[0]), 4);

	for (i = 0, r1 = 0, r2 = 0; i < 4; i++) {
		r1 = ROL32((r1 | (x1 & 0xFE000000)), 8);
		r2 = ROL32((r2 | (x2 & 0xFE000000)), 8);
		x1 <<= 7;
		x2 <<= 7;
	}
	*out++ = SWAP32(r1);
	*out++ = SWAP32(r2);
}

/**
 *
 *  Convert RID to 2 DES keys
 *
 */
void rid2keys(DWORD rid, LPBYTE key1, LPBYTE key2) {
	DWORD k[4];
	LPBYTE p = (LPBYTE)k;

	// so long as we're on LE architecture
	k[0] = k[1] = k[2] = rid;
	k[3] = k[0] & 0xFFFF;
	k[3] |= k[3] << 16;

	str2key(p, key1);
	str2key(&p[7], key2);
}

typedef struct _DES_KEY_BLOB {
	BLOBHEADER Hdr;
	DWORD dwKeySize;
	BYTE rgbKeyData[8];
} DES_KEY_BLOB;

BYTE header[] = { 0x08, 0x02, 0x00, 0x00, 0x01, 0x66, 0x00, 0x00 };




/**
 *
 *  Very similar to SAM encryption
 *
 */
void decryptHash(DWORD rid, LPBYTE pbIn, LPBYTE pbOut) {
	DWORD dwDataLen;

	HCRYPTPROV hProv;
	HCRYPTKEY hKey1, hKey2;

	DES_KEY_BLOB Blob1, Blob2;

	if (CryptAcquireContext(&hProv, NULL, NULL,
		PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {

		// initialize keys
		rid2keys(rid, Blob1.rgbKeyData, Blob2.rgbKeyData);

		Blob1.dwKeySize = 8;
		Blob2.dwKeySize = 8;

		memcpy((void*)&Blob1.Hdr, (void*)header, 8);
		memcpy((void*)&Blob2.Hdr, (void*)header, 8);

		// import keys
		CryptImportKey(hProv, (BYTE*)&Blob1, sizeof(Blob1),
			0, CRYPT_EXPORTABLE, &hKey1);

		CryptImportKey(hProv, (BYTE*)&Blob2, sizeof(Blob2),
			0, CRYPT_EXPORTABLE, &hKey2);

		dwDataLen = 8;
		CryptDecrypt(hKey1, NULL, TRUE, 0, pbIn, &dwDataLen);
		memcpy(pbOut, pbIn, 8);

		dwDataLen = 8;
		CryptDecrypt(hKey2, NULL, TRUE, 0, pbIn + 8, &dwDataLen);
		memcpy(pbOut + 8, pbIn + 8, 8);

		CryptDestroyKey(hKey2);
		CryptDestroyKey(hKey1);

		CryptReleaseContext(hProv, 0);
	}
}

// isspace() removes spaces too which I want to keep
int myIsSpace(int c) {
	return c == '\n'
		|| c == '\r'
		|| c == '\t'
		|| c == '\v'
		|| c == '\f'
		|| c==':';//for john format
}

BOOL NTDS::IsAccountInactive(DWORD dwUserCtrl) {
	static ULONG lockOutId = 0;

	/** if account is disabled, skip it */
	if ((dwUserCtrl & ADS_UF_ACCOUNTDISABLE) != 0) {
		return TRUE;
	}
	/************************************
	 * This bit never seems set even when
	 * account is locked . . .
	 *************************************/
	if ((dwUserCtrl & ADS_UF_LOCKOUT) != 0) {
		return TRUE;
	}
	/************************************
	 * To compensate for above, check the
	 * lock out time instead
	 *************************************/
	if (lockOutId == 0) {
		lockOutId = GetColumnId(ATT_LOCKOUT_TIME);
	}
	FILETIME ftLockOut = { 0, 0 };
	DWORD dwSize = 0;

	err = JetRetrieveColumn(sesId, tableId, lockOutId,
		(PVOID)&ftLockOut, sizeof(ftLockOut), &dwSize, JET_bitNil, NULL);

	if (err == JET_errSuccess && dwSize != 0) {
		if (ftLockOut.dwLowDateTime != 0
			|| ftLockOut.dwHighDateTime != 0) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL NTDS::IsAccountMachine(DWORD dwUserCtrl) {
	if ((dwUserCtrl & ADS_UF_NORMAL_ACCOUNT) == 0) {
		return TRUE;
	}
	return FALSE;
}

DWORD NTDS::GetColumnData(ULONG columnId, PVOID pbBuffer, DWORD cbBufSize) {
	DWORD dwSize = 0;

	// 如果提供了缓冲区，先清零
	if (pbBuffer) {
		ZeroMemory(pbBuffer, cbBufSize);
	}

	// 首先获取数据大小
	err = JetRetrieveColumn(sesId, tableId, columnId,
		NULL, 0, &dwSize, JET_bitNil, NULL);

	// 如果是获取大小的请求
	if (!pbBuffer) {
		return (err == JET_wrnBufferTruncated) ? dwSize : 0;
	}

	// 如果缓冲区太小
	if (dwSize > cbBufSize) {
		return 0;
	}

	// 获取实际数据
	err = JetRetrieveColumn(sesId, tableId, columnId,
		pbBuffer, cbBufSize, &dwSize, JET_bitNil, NULL);

	return (err == JET_errSuccess) ? dwSize : 0;
}

BOOL NTDS::PEKDecryptSecretDataBlock(PBYTE pbData, DWORD dwSize) {
	if (!pbData || dwSize < sizeof(SECRET_DATA)) {
		return FALSE;
	}

	PSECRET_DATA pSecret = (PSECRET_DATA)pbData;
	DWORD dataOffset = sizeof(WORD) * 2 + sizeof(DWORD) + PEK_SALT_LEN;

	if (pSecret->wType == SECRET_CRYPT_TYPE_AES) {
		dataOffset += 4;
		return DecryptAes(pekList->Data.entries[0].bKey, PEK_VALUE_LEN,
			pSecret->bSalt, PEK_SALT_LEN,
			pbData + dataOffset,
			dwSize - dataOffset);
	}
	else {
		return EncryptDecryptWithKey(pekList->Data.entries[0].bKey, PEK_VALUE_LEN,
			pSecret->bSalt, PEK_SALT_LEN, 1,
			pbData + dataOffset,
			dwSize - dataOffset);
	}
}


VOID NTDS::DisplayDecrypted(DWORD rid, PBYTE pbHash, FILE* fp,char fmt) {
	BYTE hash[16];
	char c[] = "%02x";
	c[3] = fmt;
	decryptHash(rid, pbHash, hash);
	for (int i = 0; i < 16; i++) {
		fprintf(fp,c,hash[i]);
	}
}
VOID NTDS::DumpHash(DWORD rid, PBYTE pbHash, DWORD dwLength, FILE* fp, char fmt) {
	if (!pbHash || dwLength < sizeof(SECRET_DATA)) {
		return;
	}

	PSECRET_DATA pSecret = (PSECRET_DATA)pbHash;
	DWORD offset = sizeof(SECRET_DATA);

	// 解密数据
	if (PEKDecryptSecretDataBlock(pbHash, dwLength)) {
		// 显示解密后的哈希
		DisplayDecrypted(rid, pbHash + offset, fp, fmt);
	}
	else {
		// 如果解密失败，输出空哈希
		if (dwLength == LM_HASH_LEN) {
			fprintf(fp, "aad3b435b51404eeaad3b435b51404ee");
		}
		else {
			fprintf(fp, "31d6cfe0d16ae931b73c59d7e0c089c0");
		}
	}
}




FILE* NTDS::GetOutputFile() {
	return m_outFile ? m_outFile : stdout; // 返回输出文件或标准输出
}

#define ASN1_SEQUENCE      0x30
#define ASN1_INTEGER       0x02
#define ASN1_OCTET_STRING  0x04
#define ASN1_CONTEXT_0    0xA0
#define ASN1_CONTEXT_1    0xA1

// 辅助函数：获取 ASN.1 长度
DWORD GetASN1Length(PBYTE data, DWORD& offset) {
	DWORD length = 0;
	if (data[offset] & 0x80) {
		BYTE lenBytes = data[offset] & 0x7F;
		offset++;
		for (BYTE i = 0; i < lenBytes; i++) {
			length = (length << 8) | data[offset++];
		}
	}
	else {
		length = data[offset++];
	}
	return length;
}


std::string NTDS::ParseSupplementalCredentials(PBYTE data, DWORD size, const wchar_t* userName) {
	if (!data || size == 0 || !userName) {
		return "";
	}

	try {
		// 1. 解密数据
		PSECRET_DATA pSecret = (PSECRET_DATA)data;
		if (!PEKDecryptSecretDataBlock(data, size)) {
			return "";
		}

		// 2. 计算解密后数据的偏移
		DWORD dataOffset = sizeof(WORD) * 2 + sizeof(DWORD) + PEK_SALT_LEN;
		if (pSecret->wType == SECRET_CRYPT_TYPE_AES) {
			dataOffset += 4;
		}

		PBYTE decryptedData = data + dataOffset;
		DWORD decryptedSize = size - dataOffset;

		// 3. 解析为 USER_PROPERTIES 结构
		PUSER_PROPERTIES properties = (PUSER_PROPERTIES)decryptedData;

		// 检查数据有效性和签名
		if (decryptedSize < sizeof(USER_PROPERTIES) || properties->PropertySignature != L'P') {
			return "";
		}

		// 4. 遍历属性
		PUSER_PROPERTY property = properties->UserProperties;
		for (DWORD i = 0; i < properties->PropertyCount; i++) {
			// 检查属性名称是否是 "Primary:CLEARTEXT"
			if (property->NameLength >= 32) { // 16个宽字符 = 32字节
				wchar_t nameBuf[32] = { 0 };
				wcsncpy_s(nameBuf, property->PropertyName, min(property->NameLength / 2, 31));

				if (wcscmp(nameBuf, L"Primary:CLEARTEXT") == 0) {
					// 获取属性值（十六进制字符串）
					LPSTR value = (LPSTR)((LPCBYTE)property->PropertyName + property->NameLength);
					DWORD szData = property->ValueLength / 2;

					// 解码十六进制字符串
					PBYTE binData = (PBYTE)LocalAlloc(LPTR, szData);
					if (binData) {
						// 将十六进制字符串转换为二进制数据
						for (DWORD j = 0; j < szData; j++) {
							DWORD k;
							sscanf_s(&value[j * 2], "%02x", &k);
							binData[j] = (BYTE)k;
						}

						// 明文密码是 Unicode 字符串
						std::string password;
						for (DWORD j = 0; j < szData / sizeof(wchar_t); j++) {
							wchar_t ch = ((PWSTR)binData)[j];
							if (ch >= 32 && ch <= 126) { // 可打印 ASCII 字符
								password += (char)ch;
							}
						}

						LocalFree(binData);
						return password;
					}
				}
			}

			// 移动到下一个属性
			property = (PUSER_PROPERTY)((PBYTE)property + FIELD_OFFSET(USER_PROPERTY, PropertyName) + property->NameLength + property->ValueLength);
		}
	}
	catch (...) {
		// 忽略异常
	}

	return "";
}


// 添加 ProcessHistoryHashes 函数
VOID NTDS::ProcessHistoryHashes(const wchar_t* samName, DWORD rid, ULONG lmHistoryId, ULONG ntHistoryId, FILE* out, char fmt, DWORD* pHistoryCount) {
	// 处理LM历史记录
	BYTE lmHistoryData[4096] = { 0 };
	DWORD lmHistorySize = GetColumnData(lmHistoryId, lmHistoryData, sizeof(lmHistoryData));

	// 处理NT历史记录
	BYTE ntHistoryData[4096] = { 0 };
	DWORD ntHistorySize = GetColumnData(ntHistoryId, ntHistoryData, sizeof(ntHistoryData));

	if (lmHistorySize > 0 || ntHistorySize > 0) {
		// 解密历史记录数据
		BOOL lmDecrypted = (lmHistorySize > 0) ? PEKDecryptSecretDataBlock(lmHistoryData, lmHistorySize) : FALSE;
		BOOL ntDecrypted = (ntHistorySize > 0) ? PEKDecryptSecretDataBlock(ntHistoryData, ntHistorySize) : FALSE;

		DWORD lmOffset = sizeof(SECRET_DATA);
		DWORD ntOffset = sizeof(SECRET_DATA);
		DWORD lmCount = lmDecrypted ? (lmHistorySize - lmOffset) / LM_HASH_LEN : 0;
		DWORD ntCount = ntDecrypted ? (ntHistorySize - ntOffset) / NT_HASH_LEN : 0;
		DWORD maxCount = max(lmCount, ntCount);

		for (DWORD i = 0; i < maxCount; i++) {
			fprintf(out, "%ls_history_%d:%d:", samName, i, rid);

			// LM历史记录哈希
			if (i < lmCount) {
				DumpHash(rid, lmHistoryData + lmOffset + (i * LM_HASH_LEN), LM_HASH_LEN, out, fmt);
			}
			else {
				fprintf(out, "aad3b435b51404eeaad3b435b51404ee");
			}
			fprintf(out, ":");

			// NT历史记录哈希
			if (i < ntCount) {
				DumpHash(rid, ntHistoryData + ntOffset + (i * NT_HASH_LEN), NT_HASH_LEN, out, fmt);
			}
			else {
				fprintf(out, "31d6cfe0d16ae931b73c59d7e0c089c0");
			}
			fprintf(out, ":::\n");

			(*pHistoryCount)++;
		}
	}
}

// 在 GetHashes 函数中简化历史记录处理部分
BOOL NTDS::GetHashes(char fmt, BOOL bHistory, BOOL bInactive, BOOL bMachines, BOOL bProfile, FILE* out, DWORD* pAccounts, DWORD* pMachines, DWORD* pEntries, DWORD* pHistory) {
	wchar_t samName[256], description[256], path[256];
	BYTE lmHash[256], ntHash[256], sid[256];
	DWORD rid, dwUserCtrl;
	DWORD dwAcc = 0, dwMac = 0, dwEnt = 0, dwHis = 0;

	// 获取列ID
	ULONG uacId = GetColumnId(ATT_USER_ACCOUNT_CONTROL);
	ULONG sidId = GetColumnId(ATT_OBJECT_SID);
	ULONG lmId = GetColumnId(ATT_DBCS_PWD);
	ULONG ntId = GetColumnId(ATT_UNICODE_PWD);
	ULONG samId = GetColumnId(ATT_SAM_ACCOUNT_NAME);
	ULONG descId = GetColumnId(ATT_DESCRIPTION);
	ULONG homeId = GetColumnId(ATT_HOME_DIRECTORY);
	ULONG supplementalId = m_hasClearText ? GetColumnId(ATT_SUPPLEMENTAL_CREDENTIALS) : 0;

	// 打开表
	err = JetOpenTable(sesId, dbId, "datatable", NULL, 0,
		JET_bitTableReadOnly | JET_bitTableSequential, &tableId);
	if (err != JET_errSuccess) return FALSE;

	// 移动到第一行
	err = JetMove(sesId, tableId, JET_MoveFirst, JET_bitNil);
	if (err != JET_errSuccess) {
		JetCloseTable(sesId, tableId);
		return FALSE;
	}

	do {
		// 获取用户控制标志
		if (GetColumnData(uacId, &dwUserCtrl, sizeof(dwUserCtrl)) == 0) continue;

		// 检查账户状态
		if (!bInactive && IsAccountInactive(dwUserCtrl)) continue;
		if (!bMachines && IsAccountMachine(dwUserCtrl)) continue;

		// 获取用户名
		if (GetColumnData(samId, samName, sizeof(samName)) == 0) continue;

		// 获取SID和RID
		if (GetColumnData(sidId, sid, sizeof(sid)) > 0) {
			DWORD dwCount = *GetSidSubAuthorityCount((PSID)&sid);
			rid = *GetSidSubAuthority((PSID)&sid, dwCount - 1);
			rid = _byteswap_ulong(rid);

			// 基本格式: 用户名:RID:LM哈希:NT哈希
			fprintf(out, "%ls:%d:", samName, rid);

			// LM Hash
			DWORD lmSize = GetColumnData(lmId, lmHash, sizeof(lmHash));
			if (lmSize > 0) {
				DumpHash(rid, lmHash, lmSize, out, fmt);
			}
			else {
				fprintf(out, "aad3b435b51404eeaad3b435b51404ee");
			}
			fprintf(out, ":");

			// NT Hash
			DWORD ntSize = GetColumnData(ntId, ntHash, sizeof(ntHash));
			if (ntSize > 0) {
				DumpHash(rid, ntHash, ntSize, out, fmt);
			}
			else {
				fprintf(out, "31d6cfe0d16ae931b73c59d7e0c089c0");
			}

			// 明文密码 (如果有)
			if (m_hasClearText && supplementalId) {
				BYTE supplemental[4096] = { 0 };
				DWORD supSize = GetColumnData(supplementalId, supplemental, sizeof(supplemental));

				if (supSize > 0) {
					std::string password = ParseSupplementalCredentials(supplemental, supSize, samName);
					if (!password.empty()) {
						fprintf(out, ":%s", password.c_str());
					}
				}
			}

			// 用户描述和主目录 (如果需要)
			if (bProfile) {
				std::wstring desc, home;

				if (GetColumnData(descId, description, sizeof(description)) > 0) {
					desc = description;
					desc.erase(remove_if(desc.begin(), desc.end(), myIsSpace), desc.end());
				}

				if (GetColumnData(homeId, path, sizeof(path)) > 0) {
					home = path;
					home.erase(remove_if(home.begin(), home.end(), myIsSpace), home.end());
				}

				if (!desc.empty() || !home.empty()) {
					fprintf(out, ":%ls:%ls", desc.c_str(), home.c_str());
				}
			}

			// 添加换行
			fprintf(out, "\n");

			// 更新计数
			if (IsAccountMachine(dwUserCtrl)) {
				dwMac++;
			}
			else {
				dwAcc++;
			}
			dwEnt++;
		}
	} while (JetMove(sesId, tableId, JET_MoveNext, JET_bitNil) == JET_errSuccess);

	// 更新统计信息
	if (pAccounts) *pAccounts = dwAcc;
	if (pMachines) *pMachines = dwMac;
	if (pEntries) *pEntries = dwEnt;
	if (pHistory) *pHistory = dwHis;

	// 关闭表
	JetCloseTable(sesId, tableId);
	return TRUE;
}