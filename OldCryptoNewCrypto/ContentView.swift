//
//  ContentView.swift
//  OldCryptoNewCrypto
//
//  Created by David Wagner on 14/10/2020.
//

import SwiftUI
import CryptoKit

struct ContentView: View {
    let oldKey = OldSkool.Key()
    let newKey = NewSkool.Key()

    var body: some View {
        HStack {
            Text("Old pub key:")
                .foregroundColor(.gray)
                .padding()
            Text(oldKey.publicKeyRepresentation.hexString)
                .padding()
        }
        HStack {
            Text("New pub key:")
                .foregroundColor(.gray)
                .padding()
            Text(newKey.publicKeyRepresentation.hexString)
                .padding()
        }
        HStack {
            Text("Old derived key:")
                .foregroundColor(.gray)
                .padding()
            Text(oldKey.ecdh(withX963PublicKey: newKey.publicKeyRepresentation).hexString)
                .padding()
        }
        HStack {
            Text("New derived key:")
                .foregroundColor(.gray)
                .padding()
            Text(newKey.ecdh(withX963PublicKey: oldKey.publicKeyRepresentation).hexString)
                .padding()
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

enum OldSkool {
    struct Key {
        private let privateKey: SecKey
        
        init() {
            guard let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .privateKeyUsage, nil) else {
                fatalError("Could not create access")
            }
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false,
                    kSecAttrAccessControl as String: access,
                ]
            ]
            var error: Unmanaged<CFError>?
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                fatalError("Could not create private key: \(String(describing: error))")
            }
            self.privateKey = privateKey
        }
        
        var publicKeyRepresentation: Data {
            guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                fatalError("Failed to get public key")
            }
            var error: Unmanaged<CFError>?
            guard let publicRepresentation = SecKeyCopyExternalRepresentation(publicKey, &error) else {
                fatalError("Could not get external representation of public key: \(String(describing: error))")
            }
            return publicRepresentation as Data
        }

        func ecdh(withX963PublicKey x963: Data) -> Data {
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: 256,
                kSecPublicKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false,
                ]
            ]

            var error: Unmanaged<CFError>?
            guard let publicKey = SecKeyCreateWithData(x963 as CFData, attributes as CFDictionary, &error) else {
                fatalError("Could not parse external representation: \(String(describing:error))")
            }
            let params: [CFString : Any] = [SecKeyKeyExchangeParameter.requestedSize.rawValue: 32, SecKeyKeyExchangeParameter.sharedInfo.rawValue: Data() as CFData]
            guard let derived = SecKeyCopyKeyExchangeResult(privateKey, .ecdhKeyExchangeCofactorX963SHA256, publicKey, params as CFDictionary, &error) else {
                fatalError("Could not derive key: \(String(describing:error))")
            }
            
            return derived as Data
        }
    }
}

enum NewSkool {
    struct Key {
        private let privateKey = try! SecureEnclave.P256.KeyAgreement.PrivateKey()
        
        var publicKeyRepresentation: Data {
            privateKey.publicKey.x963Representation
        }
        
        func ecdh(withX963PublicKey x963: Data) -> Data {
            guard let publicKey = try? P256.KeyAgreement.PublicKey(x963Representation: x963) else {
                fatalError("Could not parse public key representation")
            }
            guard let sharedSecret = try? privateKey.sharedSecretFromKeyAgreement(with: publicKey) else {
                fatalError("Could not generate shared secret")
            }
            
            let derived = sharedSecret.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)

            return derived.withUnsafeBytes { p in
                Data(p)
            }
        }
    }
}

extension Data {
    var hexString: String {
        self.map { String(format: "%02hhx", $0) } .joined()
    }
}
