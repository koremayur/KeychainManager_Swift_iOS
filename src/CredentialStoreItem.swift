//
//  CredentialStoreItem.swift
//  CoreClient
//
//  Created by Mayur on 03/10/17.
//  Copyright © 2017 Odocon. All rights reserved.
//
/*
 MIT License
 
 Copyright (c) 2017 Mayur Kore
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */


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
    var itemData: Data
    var isShared: Bool
    /**
     CreadentialStoreItem object to be stores inside CredentialStoreProvider.
     
     
     - parameter itemType: CredentialStoreItemType key/password. Default is none.
     - parameter itemTag: Tag/Name for the item.
     - parameter itemData: Actual data for the item to be store inside CredentialStoreProvider/Keychain.
     - parameter isShared: Is this item shared under any shared access group.
     */
    init(itemType: CredentialStoreItemType, itemTag: String, itemData: Data, isShared: Bool) {
        self.itemType = itemType
        self.itemTag = itemTag
        self.itemData = itemData
        self.isShared = isShared
    }
}
