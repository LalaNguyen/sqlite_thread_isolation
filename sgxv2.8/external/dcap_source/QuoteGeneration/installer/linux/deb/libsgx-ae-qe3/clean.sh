#!/usr/bin/env bash
#
# Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


set -e

SCRIPT_DIR=$(dirname "$0")
COMMON_DIR="${SCRIPT_DIR}/../../common/libsgx-ae-qe3"

rm -f ${SCRIPT_DIR}/libsgx-ae-qe3*.deb
rm -f ${SCRIPT_DIR}/libsgx-ae-qe3*.ddeb
rm -f ${SCRIPT_DIR}/libsgx-ae-qe3*.tar.gz
rm -f ${SCRIPT_DIR}/libsgx-ae-qe3*.tar.xz
rm -f ${SCRIPT_DIR}/libsgx-ae-qe3*.dsc
rm -f ${SCRIPT_DIR}/libsgx-ae-qe3*.changes
rm -f ${SCRIPT_DIR}/libsgx-ae-qe3*.buildinfo
rm -f ${COMMON_DIR}/gen_source.py
rm -rf ${COMMON_DIR}/output
