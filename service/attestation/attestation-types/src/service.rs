/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use crate::resource::{policy::PolicyLocation, ResourceLocation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum GetResourceOp {
    /// User in TEE environment can get resource content.
    TeeGet { resource: ResourceLocation },
    /// Vendor can only get the list of resource files that are already published in AS.
    VendorGet { vendor: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SetResourceOp {
    /// Add new resource.
    /// The vendor of each policy should be 'default' or the same with the resource.
    /// Otherwise error will be raised.
    ///
    /// If the resource already exists, the content will be overrided.
    Add {
        content: String,
        policy: Vec<String>,
    },
    /// Delete specific resource.
    Delete,
    /// Modify the content of specific resource. Other fields of the resource will be kept.
    Modify { content: String },
    /// Bind policy to specific resource.
    /// The vendor of any policy should be 'default' or the same with the resource.
    /// Otherwise error will be raised.
    Bind { policy: Vec<String> },
    /// Unbind policy of specific resource.
    /// The vendor of any policy should be 'default' or the same with the resource.
    /// Otherwise error will be raised.
    Unbind { policy: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetResourceRequest {
    pub op: SetResourceOp,
    /// The vendor of the resource should be the same with that granted in the token.
    pub resource: ResourceLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum GetResourcePolicyOp {
    /// Get specific policy under a vendor.
    GetOne { policy: PolicyLocation },
    /// Get all policy under different vendors.
    /// The returned value is a vector of policy identifer, such as '["vendor_A/example.rego", "vendor_B/example.rego"]'.
    GetAll,
    /// Get all policy under particular vendor.
    /// The returned value is a vector of policy identifer, such as '["vendor_A/example_1.rego", "vendor_A/example_2.rego"]'.
    GetAllInVendor { vendor: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SetResourcePolicyOp {
    /// Add new policy file, if it already exists, override its content.
    ///
    /// The vendor of policy should be the same with that in the token granted to the user.
    Add {
        policy: PolicyLocation,
        content: String,
    },
    /// Delete particular policy file.
    ///
    /// The vendor of policy should be the same with that in the token granted to the user.
    Delete { policy: PolicyLocation },
    /// Clear all policy files of particular vendor.
    ClearAll { vendor: String },
}
