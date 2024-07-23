# -----------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -----------------------------------------------------------------------------

import os
import json
from knack.log import get_logger
from microsoft_security_utilities_secret_masker import load_regex_patterns_from_json_file, SecretMasker
logger = get_logger(__name__)

def scan_secrets(file_path, file_type=None, result_path=None):
    file_path = os.path.abspath(file_path)
    logger.debug(f'start scanning secrets for {file_path}')
    precisely_classified_regex_patterns = load_regex_patterns_from_json_file('PreciselyClassifiedSecurityKeys.json')
    # unclassified_regex_patterns = load_regex_patterns_from_json_file('UnclassifiedPotentialSecurityKeys.json')
    # regex_patterns = precisely_classified_regex_patterns.union(unclassified_regex_patterns)
    secret_masker = SecretMasker(precisely_classified_regex_patterns)
    with open(file_path) as f:
        content = f.read()
    detected_secrets = secret_masker.detect_secrets(content)

    if not detected_secrets:
        logger.debug(f'no secrets scanned for {file_path}')
        return {"secrets_detected": False}

    if not result_path:
        file_folder = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        result_file_name = 'scan_' + file_name.replace('.', '_') + '_result.json'
        result_path = os.path.join(file_folder, result_file_name)


    with open(result_path, 'w') as f:
        scan_results = []
        for secret in detected_secrets:
            logger.debug(f'found secrets, name:{secret.name}, value:{content[secret.start:secret.end]}')
            scan_results.append({
                'name': secret.name,
                'value': content[secret.start:secret.end],
                'redaction_token': secret.redaction_token
            })
        json.dump(scan_results, f)
        logger.debug(f'store scanning results in {result_path}')
    logger.debug(f'finished scanning secrets for {file_path}')
    return {"secrets_detected": True, "result_path": result_path}


def mask_secrets(file_path, scan_result_path=None, mask_type='keep_original_file'):
    file_path = os.path.abspath(file_path)
    with open(file_path) as f:
        content = f.read()

    if not scan_result_path:
        scan_response = scan_secrets(file_path)
        if not scan_response["secrets_detected"]:
            return
        scan_result_path = scan_response["result_path"]

    with open(scan_result_path) as f:
        scan_results = json.load(f)

    for secret in scan_results:
        content = content.replace(secret["value"], secret["redaction_token"])

    if mask_type == 'keep_original_file':
        file_folder = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        original_file_name = "original_"+file_name
        os.rename(file_path, os.path.join(file_folder, original_file_name))
        with open(file_path, 'w') as f:
            f.write(content)



