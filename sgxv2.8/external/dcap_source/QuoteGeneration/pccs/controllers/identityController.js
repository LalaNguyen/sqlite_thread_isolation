/**
 *
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

const { identityService }= require('../services');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const Constants = require('../constants/');

exports.getQEIdentity = async function(req,res,next) {
    try {
        // call service
        let qeidJson = await identityService.getQEIdentity();

        // send response
        res.status(PCCS_STATUS.PCCS_STATUS_SUCCESS[0])
           .header(Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, qeidJson[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN])
           .json(qeidJson.qeid);
    }
    catch(err) {
        next(err);
    }
};

exports.getQvEIdentity = async function(req,res,next) {
    try {
        // call service 
        let qveidJson = await identityService.getQvEIdentity();

        // send response
        res.status(PCCS_STATUS.PCCS_STATUS_SUCCESS[0])
           .header(Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, qveidJson[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN])
           .json(qveidJson.qveid);
    }
    catch(err) {
        next(err);
    }
};


