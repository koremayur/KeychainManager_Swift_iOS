//
//  CredentialStoreProvider.swift
//  CoreClient
//
//  Created by Mayur on 03/10/17.
//  Copyright © 2017 Odocon. All rights reserved.
//

import Foundation

/**
 All the sensitive data used in the app like, username/password, certificates, keys are needed to be stored securely & persistently
 inside some container.
 Generally, such stores need to take into account following design considerations:
 - Defining the layout/structure for the repository of the sensitive data items
 - Design a mechanism to secure/protect the container containing these items (using encryption)
 - Provide an API using which one can interact with such a store to add/retrieve/modify/delete the items
 
 In broader terms, the Credential Store is nothing but a component satisfying all of the three criterias above.
 The layout/structure of such a store can be a standard one, like - Java Keystore, Mac OS/iOS Keychain (which is nothing but an
 encrypted SQLite DB with well defined formats for storing various items), Windows Keyring, or any other proprietary mechanism to
 achieve the same.
 
 Note that such Credential Stores generally make sure that the contents in it remain secure by encrypting the container as a whole.
 But, it's recommended that the developers encrypt the individual items being added to the store (in accordance with their application's
 logic/needs) thereby providing an additional layer of protection even in case the container level encryption is broken (or the devices
 are jailbroken/rooted). Naturally, the key to encrypt/decrypt items shall not be available obviosuly in the source code.
 
 The Credential Store APIs are key-value based where the key is - identifier to uniquely identify the secure item in store
 & value is the password/key. That's why, all the CredentialStoreProvider methods have itemTag as a parameter.
 Item values must be converted to data to be passed to the store methods.
 
 Right now, CredentialStoreProvider supports only 2 kinds of items:
 CredentialItemTypeKey - key (used for encrypting/decrypting purposes)
 CredentialItemTypePassword- the password
 */
public protocol CredentialStoreProvider {
    
    init(theSharedAccessGroupID: String?)
    /**
     Adds a credential item with given type & tag.
     
     
     parameter itemData: the actual credential data to be added.
     parameter itemType: the type of CredentialItemType into which the given credential data item classifies.
     parameter itemTag: the string that uniquely identifies the item within the credential store.
     */
    @discardableResult
    func addItem(_ credentialStoreItem: CredentialStoreItem) -> Bool
    
    /**
     Removes a credential item identified by the given type & tag.
     
     
     parameter itemType: the type of CredentialItemType into which the given credential data item classifies.
     parameter itemTag: the string that uniquely identifies the item within the credential store.
     */
    @discardableResult
    func removeItem(_ credentialStoreItem: CredentialStoreItem) -> Bool
    
    /**
     Overwrites the previous contents/data of a credential item identified by the given type & tag.
     
     
     parameter itemType: the type of CredentialItemType into which the given credential data item classifies.
     parameter itemTag: the string that uniquely identifies the item within the credential store.
     parameter newData: the new value for the credential data item.
     */
    func updateExistingItemWithNewItem(_ oldCredentialStoreItem: CredentialStoreItem, newCredentialStoreItem: CredentialStoreItem)  -> Bool
    
    /**
     Retrieves the data/value for a credential item identified by the given type & tag.
     
     
     parameter itemType: the type of CredentialItemType into which the given credential data item classifies
     parameter itemTag: the string that uniquely identifies the item within the credential store
     returns: data/value corresponding to a credential item.
     */
    func getItem(_ credentialStoreItem: CredentialStoreItem) -> Data?
    
    /**
     Removes all the items from the credential store.
     
     
     returns: YES if all the items were removed successfully, else NO.
     */
    @discardableResult
    func deleteAllItems() -> Bool
}
