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

const { fmspc_tcbs }= require('./models/');
const Constants = require('../constants/index.js');
const PccsError = require('../utils/PccsError.js');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const {Sequelize, sequelize} = require('./models/');

// Update or insert a record in JSON format
exports.upsertFmspcTcb = async function(tcbinfoJson) {
    return await fmspc_tcbs.upsert({
        fmspc: tcbinfoJson.fmspc,
        tcbinfo: JSON.stringify(tcbinfoJson.tcbinfo),
        root_cert_id: Constants.PROCESSOR_ROOT_CERT_ID,
        signing_cert_id: Constants.PROCESSOR_SIGNING_CERT_ID
    });
}

//Query TCBInfo by fmspc
exports.getTcbInfo = async function(fmspc) {
    const sql = 'select a.*,' +
              ' (select cert from pcs_certificates where id=a.root_cert_id) as root_cert,' +
              ' (select cert from pcs_certificates where id=a.signing_cert_id) as signing_cert' +
              ' from fmspc_tcbs a ' +
              ' where a.fmspc=$fmspc';
    const tcbinfo = await sequelize.query(sql,
        {
            type:  sequelize.QueryTypes.SELECT,
            bind: { fmspc : fmspc }
        });
    if (tcbinfo.length == 0)
        return null;
    else if (tcbinfo.length == 1 ){
        if (tcbinfo[0].root_cert != null && tcbinfo[0].signing_cert != null)
            return tcbinfo[0];
        else return null;
    }
    else 
        throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTERNAL_ERROR);
}

//Query all TCBInfos
exports.getAllTcbs = async function(){
    return await fmspc_tcbs.findAll();
}

