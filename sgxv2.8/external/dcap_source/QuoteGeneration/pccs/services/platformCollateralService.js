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
const logger = require('../utils/Logger.js');
const platformsDao = require('../dao/platformsDao.js');
const pckcertDao = require('../dao/pckcertDao.js');
const platformTcbsDao = require('../dao/platformTcbsDao.js');
const fmspcTcbDao = require('../dao/fmspcTcbDao.js');
const pckcrlDao = require('../dao/pckcrlDao.js');
const qeidentityDao = require('../dao/qeidentityDao.js');
const qveidentityDao = require('../dao/qveidentityDao.js');
const pckCertchainDao = require('../dao/pckCertchainDao.js');
const pcsCertificatesDao = require('../dao/pcsCertificatesDao.js');
const PccsError = require('../utils/PccsError.js');
const Config = require('config');
const PCCS_STATUS = require('../constants/pccs_status_code.js');
const Constants = require('../constants/index.js');
const Ajv = require('ajv');
const Schema = require('./pccs_schemas.js');
const {Sequelize, sequelize} = require('../dao/models/');
const X509 = require('../x509/x509.js');
const PckLib = require('../lib_wrapper/pcklib_wrapper.js');

const ajv = new Ajv();

toUpper=function(str){
    if (str)
        return str.toUpperCase();
    else return str;
}

verify_cert=function(root1,root2){
    if (Boolean(root1) && Boolean(root2) && root1 != root2)
        return false;
    return true;
}

exports.addPlatformCollateral=async function(collateralJson) {
    return await sequelize.transaction(async (t)=>{
        //check parameters
        let valid = ajv.validate(Schema.PLATFORM_COLLATERAL_SCHEMA, collateralJson);
        if (!valid) {
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
        }

        // process the collaterals
        let platforms = collateralJson.platforms;
        let collaterals = collateralJson.collaterals;
        let tcbinfos = collaterals.tcbinfos;

        // For every platform we have a set of PCK certs
        for (const platform_certs of collaterals.pck_certs) {
            // Flush and add certs for this platform
            await pckcertDao.deleteCerts(platform_certs.qe_id, platform_certs.pce_id);
            for (const cert of platform_certs.certs) {
                await pckcertDao.upsertPckCert(toUpper(platform_certs.qe_id), 
                    toUpper(platform_certs.pce_id), 
                    toUpper(cert.tcbm), 
                    unescape(cert.cert));
            }

            // We will update platforms both in cache and in the request list
            // make a full list based on the cache data and the input data
            let cached_platform_tcbs = await platformTcbsDao.getPlatformTcbsById(platform_certs.qe_id, platform_certs.pce_id);
            let new_platforms = platforms.filter(o => (o.pce_id == platform_certs.pce_id && o.qe_id == platform_certs.qe_id));
            var platforms_all = [];
            for (const cached_platform of cached_platform_tcbs) {
                platforms_all.push({
                    "qe_id": cached_platform.qe_id,
                    "pce_id": cached_platform.pce_id,
                    "cpu_svn": cached_platform.cpu_svn,
                    "pce_svn": cached_platform.pce_svn
                });
            }
            for (const new_platform of new_platforms) {
                platforms_all.push({
                    "qe_id": new_platform.qe_id,
                    "pce_id": new_platform.pce_id,
                    "cpu_svn": new_platform.cpu_svn,
                    "pce_svn": new_platform.pce_svn
                });
            }
            // Remove duplicates, can be optimized (TODO)
            var platforms_cleaned = platforms_all.filter((element, index, self) =>
                index === self.findIndex((t) => (t.qe_id === element.qe_id && t.pce_id === element.pce_id
                                                && t.cpu_svn === element.cpu_svn && t.pce_svn === element.pce_svn)));

            let mycerts = platform_certs.certs;
            if (mycerts == null || mycerts.length == 0) {
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
            }
            // parse arbitary cert to get fmspc value
            const x509 = new X509();
            if (!x509.parseCert(unescape(mycerts[0].cert))) {
                logger.error('Invalid certificate format.');
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
            }

            let fmspc = x509.fmspc;
            if (fmspc == null) {
                logger.error('Invalid certificate format.');
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
            }
            // get tcbinfo for the fmspc
            let tcbinfo = tcbinfos.find(
                o => (o.fmspc === fmspc)     
            );
            if (tcbinfo == null) {
                logger.error('Can\'t find TCB info.');
                throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
            }

            var pem_certs = mycerts.map(o => unescape(o.cert));
            for (var platform of platforms_cleaned) {
                // get the best cert with PCKCertSelectionTool
                let cert_index = PckLib.pck_cert_select(platform.cpu_svn, 
                    platform.pce_svn, platform.pce_id, JSON.stringify(tcbinfo.tcbinfo), pem_certs, pem_certs.length);
                if (cert_index == -1) {
                    logger.error('Failed to select the best certificate for ' + platform);
                    throw new PccsError(PCCS_STATUS.PCCS_STATUS_INVALID_REQ);
                }

                // update platform_tcbs table
                await platformTcbsDao.upsertPlatformTcbs(
                    toUpper(platform.qe_id), 
                    toUpper(platform.pce_id), 
                    toUpper(platform.cpu_svn), 
                    toUpper(platform.pce_svn),
                    mycerts[cert_index].tcbm 
                );
            }

            // update platforms table for new platforms only
            for (platform of new_platforms) {
                // update platforms/pck_cert table
                await platformsDao.upsertPlatform(
                    toUpper(platform.qe_id), 
                    toUpper(platform.pce_id), 
                    toUpper(platform.platform_manifest), 
                    toUpper(platform.enc_ppid), 
                    toUpper(fmspc)
                );
            }
        }
        
        // loop through tcbinfos
        for (const tcbinfo of tcbinfos) {
            tcbinfo.fmspc = toUpper(tcbinfo.fmspc);
            await fmspcTcbDao.upsertFmspcTcb(tcbinfo);
        }

        // Update or insert PCK CRL
        if (collaterals.pckcacrl) {
            await pckcrlDao.upsertPckCrl(Constants.CA_PROCESSOR, unescape(collaterals.pckcacrl));
        }

        // Update or insert QE Identity
        if (collaterals.qeidentity) {
            await qeidentityDao.upsertQEIdentity(collaterals.qeidentity);
        }

        // Update or insert QvE Identity
        if (collaterals.qveidentity) {
            await qveidentityDao.upsertQvEIdentity(collaterals.qveidentity);
        }

        // Update or insert PCK Certchain
        await pckCertchainDao.upsertPckCertchain();

        // Update or insert PCS certificates
        let rootCert = new Array();
        if (Boolean(collaterals.certificates[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN])) {
            rootCert[0] = await pcsCertificatesDao.upsertPckCertificateIssuerChain(collaterals.certificates[Constants.SGX_PCK_CERTIFICATE_ISSUER_CHAIN]);
        }
        if (Boolean(collaterals.certificates[Constants.SGX_TCB_INFO_ISSUER_CHAIN])) {
            rootCert[1] = await pcsCertificatesDao.upsertTcbInfoIssuerChain(collaterals.certificates[Constants.SGX_TCB_INFO_ISSUER_CHAIN]);
        }
        if (Boolean(collaterals.certificates[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN])) {
            rootCert[2] = await pcsCertificatesDao.upsertPckCertificateIssuerChain(collaterals.certificates[Constants.SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN]);
        }
        if (!verify_cert(rootCert[0], rootCert[1]) ||
            !verify_cert(rootCert[0], rootCert[2]) ||
            !verify_cert(rootCert[1], rootCert[2])) {
            throw new PccsError(PCCS_STATUS.PCCS_STATUS_INTEGRITY_ERROR);
        }

        // Update or insert rootcacrl
        if (collaterals.rootcacrl) {
            await pcsCertificatesDao.upsertRootCACrl(unescape(collaterals.rootcacrl));
        }
    });
}

