//
//  CredentialStoreItem.swift
//  CoreClient
//
//  Created by Mayur on 03/10/17.
//  Copyright © 2017 Odocon. All rights reserved.
//

import Foundation

///Keychain related constants.
public enum CredentialStoreItemType: Int {
    case none = -1
    case key = 0
    case password
}

///This class encapsulates all the details for an item to be stored inside CredentialStoreProvider.
open class CredentialStoreItem {
    var itemType: CredentialStoreItemType
    var itemTag: String
    var itemData: Data?
    var isShared: Bool
    /**
     CreadentialStoreItem object to be stores inside CredentialStoreProvider.
     
     
     - parameter itemType: CredentialStoreItemType key/password. Default is none.
     - parameter itemTag: Tag/Name for the item.
     - parameter itemData: Actual data for the item to be store inside CredentialStoreProvider/Keychain.
     - parameter isShared: Is this item shared under any shared access group.
     */
    public init(itemType: CredentialStoreItemType, itemTag: String, itemData: Data?, isShared: Bool) {
        self.itemType = itemType
        self.itemTag = itemTag
        self.itemData = itemData
        self.isShared = isShared
    }
}
