/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"
#include "plaintextstore_p.h"

#include <windows.h>
#include <wincrypt.h>

#include <memory>

using namespace QKeychain;

#include <wincred.h>

void ReadPasswordJobPrivate::scheduledStart() {
    LPCWSTR name = (LPCWSTR)key.utf16();
    PCREDENTIALW cred;

    if (!CredReadW(name, CRED_TYPE_GENERIC, 0, &cred)) {
        Error error;
        QString msg;
        switch(GetLastError()) {
        case ERROR_NO_SUCH_LOGON_SESSION:
            error = NoSuchLogonSession;
            msg = tr("No such logon session");
            break;
        case ERROR_INVALID_PARAMETER:
            error = InvalidParameter;
            msg = tr("Invalid parameter");
            break;
        case ERROR_INVALID_FLAGS:
            error = InvalidFlags;
            msg = tr("Invalid flags");
            break;
        case ERROR_BAD_USERNAME:
            error = BadUserame;
            msg = tr("Bad username");
            break;
        case ERROR_NOT_FOUND:
            error = EntryNotFound;
            msg = tr("Password entry not found");
            break;
        case SCARD_E_NO_READERS_AVAILABLE:
            error = NoReadersAvailable;
            msg = tr("Smart card reader is not available");
            break;
        case SCARD_E_NO_SMARTCARD:
        case SCARD_W_REMOVED_CARD:
            error = NoSmartcard;
            msg = tr("Smart card not present");
            break;
        case SCARD_W_WRONG_CHV:
            error = BadSmartcardPin;
            msg = tr("Bad pin");
            break;
        default:
            error = OtherError;
            msg = tr("Could not decrypt data");
            break;
        }

        q->emitFinishedWithError( error, msg );
        return;
    }

    data.first = QByteArray((char*)cred->CredentialBlob, cred->CredentialBlobSize);

    for (DWORD i=0; i < cred->AttributeCount; i++) {
        const CREDENTIAL_ATTRIBUTEW &cred_attr = cred->Attributes[i];
        const QString attr_name{ QString::fromUtf16((const ushort *)cred_attr.Keyword) };
        data.second[attr_name] = QByteArray((char *) cred_attr.Value, cred_attr.ValueSize);
    }

    CredFree(cred);

    q->emitFinished();
}

void WritePasswordJobPrivate::scheduledStart() {
    CREDENTIALW cred;
    char *pwd = data.first.data();
    LPWSTR name = (LPWSTR)key.utf16();
    const Attributes &attrs = data.second;

    memset(&cred, 0, sizeof(cred));
    cred.Comment = const_cast<wchar_t*>(L"QtKeychain");
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = name;
    cred.CredentialBlobSize = data.first.size();
    cred.CredentialBlob = (LPBYTE)pwd;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    if (attrs.size() > 0) {
        cred.AttributeCount = attrs.size();
        cred.Attributes = new CREDENTIAL_ATTRIBUTEW[cred.AttributeCount];
        QKeychain::AttributesIterator iter(attrs);
        DWORD i = 0;
        while (iter.hasNext()) {
            iter.next();
            cred.Attributes[i].Keyword = (LPWSTR) iter.key().utf16();
            cred.Attributes[i].ValueSize = iter.value().length();
            cred.Attributes[i].Value = (LPBYTE) iter.value().data();
            i++;
        }
    }

    if (CredWriteW(&cred, 0)) {
        q->emitFinished();
        delete[] cred.Attributes;
        return;
    }

    delete[] cred.Attributes;

    DWORD err = GetLastError();

    // Detect size-exceeded errors and provide nicer messages.
    // Unfortunately these error codes aren't documented.
    // Found empirically on Win10 1803 build 17134.523.
    if (err == RPC_X_BAD_STUB_DATA) {
        const size_t maxBlob = CRED_MAX_CREDENTIAL_BLOB_SIZE;
        if (cred.CredentialBlobSize > maxBlob) {
            q->emitFinishedWithError(
                OtherError,
                tr("Credential size exceeds maximum size of %1").arg(maxBlob));
            return;
        }
    }
    if (err == RPC_S_INVALID_BOUND) {
        const size_t maxTargetName = CRED_MAX_GENERIC_TARGET_NAME_LENGTH;
        if (key.size() > maxTargetName) {
            q->emitFinishedWithError(
                OtherError,
                tr("Credential key exceeds maximum size of %1").arg(maxTargetName));
            return;
        }
    }

    q->emitFinishedWithError( OtherError, tr("Writing credentials failed: Win32 error code %1").arg(err) );
}

void DeletePasswordJobPrivate::scheduledStart() {
    LPCWSTR name = (LPCWSTR)key.utf16();

    if (!CredDeleteW(name, CRED_TYPE_GENERIC, 0)) {
        Error error;
        QString msg;
        switch(GetLastError()) {
        case ERROR_NO_SUCH_LOGON_SESSION:
            error = NoSuchLogonSession;
            msg = tr("No such logon session");
            break;
        case ERROR_INVALID_PARAMETER:
            error = InvalidParameter;
            msg = tr("Invalid parameter");
            break;
        case ERROR_INVALID_FLAGS:
            error = InvalidFlags;
            msg = tr("Invalid flags");
            break;
        case ERROR_BAD_USERNAME:
            error = BadUserame;
            msg = tr("Bad username");
            break;
        case ERROR_NOT_FOUND:
            error = EntryNotFound;
            msg = tr("Password entry not found");
            break;
        case SCARD_E_NO_READERS_AVAILABLE:
            error = NoReadersAvailable;
            msg = tr("Smart card reader is not available");
            break;
        case SCARD_E_NO_SMARTCARD:
        case SCARD_W_REMOVED_CARD:
            error = NoSmartcard;
            msg = tr("Smart card not present");
            break;
        case SCARD_W_WRONG_CHV:
            error = BadSmartcardPin;
            msg = tr("Bad pin");
            break;
        default:
            error = OtherError;
            msg = tr("Could not decrypt data");
            break;
        }

        q->emitFinishedWithError( error, msg );
    } else {
        q->emitFinished();
    }
}


void ReadPasswordJobPrivateCustom::scheduledStart() {
    PlainTextStore plainTextStore( q->service(), q->settings() );
    QByteArray encrypted = plainTextStore.readData( key );
    if ( plainTextStore.error() != NoError ) {
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
        return;
    }

    DATA_BLOB blob_in, blob_out;

    blob_in.pbData = reinterpret_cast<BYTE*>( encrypted.data() );
    blob_in.cbData = encrypted.size();

    const BOOL ret = CryptUnprotectData( &blob_in,
                                        NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         0,
                                         &blob_out );
    if ( !ret ) {
        q->emitFinishedWithError( OtherError, tr("Could not decrypt data") );
        return;
    }

    data = QByteArray( reinterpret_cast<char*>( blob_out.pbData ), blob_out.cbData );
    SecureZeroMemory( blob_out.pbData, blob_out.cbData );
    LocalFree( blob_out.pbData );

    q->emitFinished();
}

void WritePasswordJobPrivateCustom::scheduledStart() {
    DATA_BLOB blob_in, blob_out;
    blob_in.pbData = reinterpret_cast<BYTE*>( data.data() );
    blob_in.cbData = data.size();
    const BOOL res = CryptProtectData( &blob_in,
                                       L"QKeychain-encrypted data",
                                       NULL,
                                       NULL,
                                       NULL,
                                       0,
                                       &blob_out );
    if ( !res ) {
        q->emitFinishedWithError( OtherError, tr("Encryption failed") ); //TODO more details available?
        return;
    }

    const QByteArray encrypted( reinterpret_cast<char*>( blob_out.pbData ), blob_out.cbData );
    LocalFree( blob_out.pbData );

    PlainTextStore plainTextStore( q->service(), q->settings() );
    plainTextStore.write( key, encrypted, Binary );
    if ( plainTextStore.error() != NoError ) {
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
        return;
    }

    q->emitFinished();
}

void DeletePasswordJobPrivateCustom::scheduledStart() {
    PlainTextStore plainTextStore( q->service(), q->settings() );
    plainTextStore.remove( key );
    if ( plainTextStore.error() != NoError ) {
        q->emitFinishedWithError( plainTextStore.error(), plainTextStore.errorString() );
    } else {
        q->emitFinished();
    }
}
