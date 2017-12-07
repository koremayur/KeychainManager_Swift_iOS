//
//  KeychainManager.swift
//  CoreClient
//
//  Created by Mayur on 04/10/17.
//  Copyright © 2017 Odocon. All rights reserved.
//

import Foundation

//The following strings are used as a suffix to the itemTag string passed to KeychainManager methods.
//The resulting string is used as the values for attributes - kSecAttrAccount & kSecAttrService respectively.
let SecurityKeychainItemAccountAttributeSuffix = "KMPasswordAccount"
let SecurityKeychainItemServiceAttributeSuffix = "KMPasswordService"

public class KeychainManager: CredentialStoreProvider {
    var sharedKeychainAccessGroup: String?
    
    required public init(theSharedAccessGroupID: String?) {
        sharedKeychainAccessGroup = theSharedAccessGroupID
    }
    
    @discardableResult
    public func addItem(_ credentialStoreItem: CredentialStoreItem) -> Bool {
        var attributes: [AnyHashable: Any] = [:]
        
        if credentialStoreItem.isShared, let accessGroup = sharedKeychainAccessGroup {
            attributes[kSecAttrAccessGroup as AnyHashable] = accessGroup
        }
        
        if credentialStoreItem.itemType == CredentialStoreItemType.key {
            attributes[kSecClass as AnyHashable] = kSecClassKey
            attributes[kSecAttrApplicationTag as AnyHashable] = credentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            attributes[kSecAttrKeyType as AnyHashable] = kSecAttrKeyTypeRSA
            attributes[kSecAttrKeySizeInBits as AnyHashable] = Int(256)
            attributes[kSecAttrEffectiveKeySize as AnyHashable] = Int(256)
            attributes[kSecAttrCanEncrypt as AnyHashable] = kCFBooleanTrue
            attributes[kSecAttrCanDecrypt as AnyHashable] = kCFBooleanTrue
            
            attributes[kSecAttrCanDerive as AnyHashable] = kCFBooleanFalse
            attributes[kSecAttrCanSign as AnyHashable] = kCFBooleanFalse
            attributes[kSecAttrCanVerify as AnyHashable] = kCFBooleanFalse
            attributes[kSecAttrCanWrap as AnyHashable] = kCFBooleanFalse
            attributes[kSecAttrCanUnwrap as AnyHashable] = kCFBooleanFalse
        } else if credentialStoreItem.itemType == CredentialStoreItemType.password {
            attributes[kSecClass as AnyHashable] = kSecClassGenericPassword
            attributes[kSecAttrGeneric as AnyHashable] = credentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            
            //Service attribute
            let serviceAttributeValue: String = credentialStoreItem.itemTag + SecurityKeychainItemServiceAttributeSuffix
            attributes[kSecAttrService as AnyHashable] = serviceAttributeValue.data(using: String.Encoding.utf8)
            
            let accountAttributeValue: String = credentialStoreItem.itemTag + SecurityKeychainItemAccountAttributeSuffix
            attributes[kSecAttrAccount as AnyHashable] = accountAttributeValue.data(using: String.Encoding.utf8)
        }
        
        //Removing item if it exists
        SecItemDelete(attributes as CFDictionary)
        
        //Set the actual item data
        attributes[kSecValueData as AnyHashable] = credentialStoreItem.itemData
        
        let keychainError: OSStatus = SecItemAdd(attributes as CFDictionary, nil)
        if keychainError == noErr {
            print("[KeychainManager] Success: Added item with tag: \((credentialStoreItem.itemTag).debugDescription), Status = \(keychainError)")
            return true
        }
        print("[KeychainManager] Error: Couldn't add item with tag: \((credentialStoreItem.itemTag).debugDescription), Status = \(keychainError)")
        return false
    }
    
    @discardableResult
    public func removeItem(_ credentialStoreItem: CredentialStoreItem) -> Bool {
        var queryAttributes: [AnyHashable : Any] = [:]
        
        if credentialStoreItem.isShared, let accessGroup = sharedKeychainAccessGroup {
            queryAttributes[kSecAttrAccessGroup as AnyHashable] = accessGroup
        }
        
        if credentialStoreItem.itemType == CredentialStoreItemType.key {
            queryAttributes[kSecClass as AnyHashable] = kSecClassKey
            queryAttributes[kSecAttrApplicationTag as AnyHashable] = credentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            queryAttributes[kSecAttrKeyType as AnyHashable] = kSecAttrKeyTypeRSA
        } else if credentialStoreItem.itemType == CredentialStoreItemType.password {
            queryAttributes[kSecClass as AnyHashable] = kSecClassGenericPassword
            queryAttributes[kSecAttrGeneric as AnyHashable] = credentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            
            //Service attribute
            let serviceAttributeValue: String = credentialStoreItem.itemTag + SecurityKeychainItemServiceAttributeSuffix
            queryAttributes[kSecAttrService as AnyHashable] = serviceAttributeValue.data(using: String.Encoding.utf8)
            
            let accountAttributeValue: String = credentialStoreItem.itemTag + SecurityKeychainItemAccountAttributeSuffix
            queryAttributes[kSecAttrAccount as AnyHashable] = accountAttributeValue.data(using: String.Encoding.utf8)
        }
        
        let keychainError: OSStatus = SecItemDelete(queryAttributes as CFDictionary)
        if keychainError == noErr {
            print("[KeychainManager] Success: Deleted item with tag: \((credentialStoreItem.itemTag).debugDescription) status = \(keychainError)")
            return true
        }
        print("[KeychainManager] Error: Couldn't delete item with tag: \((credentialStoreItem.itemTag).debugDescription), status = \(keychainError)")
        return false
    }
    
    @discardableResult
    public func updateExistingItemWithNewItem(_ oldCredentialStoreItem: CredentialStoreItem, newCredentialStoreItem: CredentialStoreItem)  -> Bool {
        var queryAttributes: [AnyHashable : Any] = [:]
        
        if oldCredentialStoreItem.isShared, let accessGroup = sharedKeychainAccessGroup {
            queryAttributes[kSecAttrAccessGroup as AnyHashable] = accessGroup
        }
        
        if oldCredentialStoreItem.itemType == CredentialStoreItemType.key {
            queryAttributes[kSecClass as AnyHashable] = kSecClassKey
            queryAttributes[kSecAttrApplicationTag as AnyHashable] = oldCredentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            queryAttributes[kSecAttrKeyType as AnyHashable] = kSecAttrKeyTypeRSA
        } else if oldCredentialStoreItem.itemType == CredentialStoreItemType.password {
            queryAttributes[kSecClass as AnyHashable] = kSecClassGenericPassword
            queryAttributes[kSecAttrGeneric as AnyHashable] = oldCredentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            
            //Service attribute
            let serviceAttributeValue: String = oldCredentialStoreItem.itemTag + SecurityKeychainItemServiceAttributeSuffix
            queryAttributes[kSecAttrService as AnyHashable] = serviceAttributeValue.data(using: String.Encoding.utf8)
            
            let accountAttributeValue: String = oldCredentialStoreItem.itemTag + SecurityKeychainItemAccountAttributeSuffix
            queryAttributes[kSecAttrAccount as AnyHashable] = accountAttributeValue.data(using: String.Encoding.utf8)
        }
        
        //Actual value to be updated with new data.
        let attributesToUpdate = [kSecValueData as AnyHashable : newCredentialStoreItem.itemData]
        
        let keychainError: OSStatus = SecItemUpdate(queryAttributes as CFDictionary, attributesToUpdate as CFDictionary)
        if keychainError == noErr {
            print("[KeychainManager] Success: Updated item with tag: \((oldCredentialStoreItem.itemTag).debugDescription) status = \(keychainError)")
            return true
        } else if keychainError == errSecItemNotFound {
            print("[KeychainManager] Error: Couldn't update item with tag: \((oldCredentialStoreItem.itemTag).debugDescription), status = \(keychainError): errSecItemNotFound")
        }
        print("[KeychainManager] Error: Couldn't update item with tag: \((oldCredentialStoreItem.itemTag).debugDescription), status = \(keychainError)")
        return false
    }
    
    public func getItem(_ credentialStoreItem: CredentialStoreItem) -> Data? {
        var queryAttributes: [AnyHashable : Any] = [:]
        
        if credentialStoreItem.isShared, let accessGroup = sharedKeychainAccessGroup {
            queryAttributes[kSecAttrAccessGroup as AnyHashable] = accessGroup
        }
 
        if credentialStoreItem.itemType == CredentialStoreItemType.key {
            queryAttributes[kSecClass as AnyHashable] = kSecClassKey
            queryAttributes[kSecAttrApplicationTag as AnyHashable] = credentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            queryAttributes[kSecAttrKeyType as AnyHashable] = kSecAttrKeyTypeRSA
        } else if credentialStoreItem.itemType == CredentialStoreItemType.password {
            queryAttributes[kSecClass as AnyHashable] = kSecClassGenericPassword
            queryAttributes[kSecAttrGeneric as AnyHashable] = credentialStoreItem.itemTag.data(using: String.Encoding.utf8)
            
            //Service attribute
            let serviceAttributeValue: String = credentialStoreItem.itemTag + SecurityKeychainItemServiceAttributeSuffix
            queryAttributes[kSecAttrService as AnyHashable] = serviceAttributeValue.data(using: String.Encoding.utf8)
            
            let accountAttributeValue: String = credentialStoreItem.itemTag + SecurityKeychainItemAccountAttributeSuffix
            queryAttributes[kSecAttrAccount as AnyHashable] = accountAttributeValue.data(using: String.Encoding.utf8)
        }
        
        queryAttributes[kSecReturnData as AnyHashable] = NSNumber.init(value: true)
        
        var itemData: AnyObject?
        let keychainError: OSStatus = SecItemCopyMatching(queryAttributes as CFDictionary, &itemData)
        if keychainError == noErr {
            print("[KeychainManager] Success: Get item with tag: \((credentialStoreItem.itemTag).debugDescription), status = \(keychainError)")
            return itemData as? Data
        }
        print("[KeychainManager] Error: Get item with tag: \((credentialStoreItem.itemTag).debugDescription), status = \(keychainError)")
        return nil
    }
    
    @discardableResult
    public func deleteAllItems() -> Bool {
        var status: Bool = true
        
        let keychainItemTypes: NSArray = [kSecClassKey as AnyHashable, kSecClassGenericPassword as AnyHashable, kSecClassInternetPassword as AnyHashable, kSecClassCertificate as AnyHashable, kSecClassIdentity as AnyHashable]
        
        for secItemClass in keychainItemTypes {
            //Remove from app specific private keychain.
            var queryAttributes = [kSecClass as AnyHashable : secItemClass]
            var keychainError: OSStatus = SecItemDelete(queryAttributes as CFDictionary)
            print("Keychain item with type: \(kSecClassKey) deletion status = \(keychainError)")
            status = (keychainError == errSecSuccess)
            
            //Remove from shared keychain.
            if let accessGroup = sharedKeychainAccessGroup {
                queryAttributes = [kSecClass as AnyHashable : secItemClass, kSecAttrAccessGroup as AnyHashable : accessGroup]
                keychainError = SecItemDelete(queryAttributes as CFDictionary)
                print("Shared keychain item with type: \(kSecClassKey) deletion status = \(keychainError)")
                status = (keychainError == errSecSuccess)
            }
        }
        return status
    }
}
