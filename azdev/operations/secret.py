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


def _validate_data_path(file_path=None, directory_path=None, data=None):
    if file_path and directory_path:
        raise ValueError('Can not specify file path and directory path at the same time')
    if file_path and data:
        raise ValueError('Can not specify file path and raw string at the same time')
    if directory_path and data:
        raise ValueError('Can not specify directory path and raw string at the same time')
    if not file_path and not directory_path and not data:
        raise ValueError('No file path ot directory path or raw string provided')

    if directory_path and not os.path.isdir(directory_path):
        raise ValueError(f'invalid directory path:{directory_path}')
    if file_path and not os.path.isfile(file_path):
        raise ValueError(f'invalid file path:{file_path}')


def _scan_secrets_for_string(data, custom_pattern=None):
    if not data:
        return None
    regex_patterns = load_regex_patterns_from_json_file('PreciselyClassifiedSecurityKeys.json')
    if custom_pattern:
        if os.path.isfile(custom_pattern):
            custom_pattern = json.load(custom_pattern)
        regex_patterns = regex_patterns.union(custom_pattern)
    secret_masker = SecretMasker(regex_patterns)
    detected_secrets = secret_masker.detect_secrets(data)
    secrets = []
    for secret in detected_secrets:
        secrets.append({
            'secret_name': secret.name,
            'secret_value': data[secret.start:secret.end],
            'redaction_token': secret.redaction_token
        })
    return secrets


def scan_secrets(file_path=None, directory_path=None, recursive=False, data=None,
                 save_scan_result=None, scan_result_path=None, custom_pattern=None):
    _validate_data_path(file_path=file_path, directory_path=directory_path, data=data)
    target_files = []
    scan_results = {}
    if directory_path:
        directory_path = os.path.abspath(directory_path)
        if recursive:
            for root, dirs, files in os.walk(directory_path):
                target_files.extend(os.path.join(root, file) for file in files)
        else:
            for file in os.listdir(directory_path):
                file = os.path.join(directory_path, file)
                if os.path.isfile(file):
                    target_files.append(file)
    if file_path:
        file_path = os.path.abspath(file_path)
        target_files.append(file_path)

    if data:
        secrets = _scan_secrets_for_string(data, custom_pattern)
        if secrets:
            scan_results['raw_data'] = secrets
    elif target_files:
        for target_file in target_files:
            logger.debug(f'start scanning secrets for {target_file}')
            with open(target_file) as f:
                data = f.read()
            if not data:
                continue
            secrets = _scan_secrets_for_string(data, custom_pattern)
            logger.debug(f'{len(secrets)} secrets found for {target_file}')
            if secrets:
                scan_results[target_file] = secrets

    if not save_scan_result:
        return {
            'secrets_detected': True if scan_results else False,
            'scan_results': scan_results
        }

    if not scan_results:
        return {'secrets_detected': False, 'scan_result_path': None}

    if not scan_result_path:
        from azdev.utilities.config import get_azdev_config_dir
        from datetime import datetime
        file_folder = os.path.join(get_azdev_config_dir(), 'scan_results')
        if not os.path.exists(file_folder):
            os.mkdir(file_folder, 0o755)
        file_name = file_path or directory_path or datetime.now().strftime('%Y%m%d%H%M%S')
        result_file_name = 'scan_result_' + file_name.replace('.', '_') + '.json'
        scan_result_path = os.path.join(file_folder, result_file_name)

    with open(scan_result_path, 'w') as f:
        json.dump(scan_results, f)
        logger.debug(f'store scanning results in {scan_result_path}')
    return {'secrets_detected': True, 'scan_result_path': os.path.abspath(scan_result_path)}


def _mask_secret_for_string(data, secret, redaction_type=None):
    if redaction_type == 'FIXED_VALUE':
        data = data.replace(secret['secret_value'], '+++')
    elif redaction_type == 'FIXED_LENGTH':
        data = data.replace(secret['secret_value'], '+' * len(secret['secret_value']))
    elif redaction_type == 'SECRET_NAME':
        data = data.replace(secret['secret_value'], secret['secret_name'])
    else:
        data = data.replace(secret['secret_value'], secret['redaction_token'])
    return data


def mask_secrets(file_path=None, directory_path=None, recursive=False, data=None,
                 save_scan_result=None, scan_result_path=None, custom_pattern=None,
                 saved_scan_result_path=None, redaction_type='FIXED_VALUE', yes=None):
    scan_results = {}
    if saved_scan_result_path:
        if not os.path.isfile(saved_scan_result_path):
            raise ValueError(f'invalid saved scan result path:{saved_scan_result_path}')
        with open(saved_scan_result_path) as f:
            saved_scan_results = json.load(f)
        # filter saved scan results to keep those related with specified file(s)
        _validate_data_path(file_path=file_path, directory_path=directory_path, data=data)
        if file_path:
            file_path = os.path.abspath(file_path)
            if file_path in saved_scan_results:
                scan_results[file_path] = saved_scan_results[file_path]
        elif directory_path:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        file_full = os.path.join(root, file)
                        if file_full in saved_scan_results:
                            scan_results[file_full] = saved_scan_results[file_full]
            else:
                for file in os.listdir(directory_path):
                    file_full = os.path.join(directory_path, file)
                    if file_full in saved_scan_results:
                        scan_results[file_full] = saved_scan_results[file_full]
        else:
            scan_results['raw_data'] = saved_scan_results['raw_data']
    else:
        scan_response = scan_secrets(file_path=file_path, directory_path=directory_path, recursive=recursive, data=data,
                                     save_scan_result=save_scan_result, scan_result_path=scan_result_path,
                                     custom_pattern=custom_pattern)
        if save_scan_result and scan_response['scan_result_path']:
            with open(scan_response['scan_result_path']) as f:
                scan_results = json.load(f)
        elif not save_scan_result:
            scan_results = scan_response['scan_results']

    if not scan_results:
        logger.warning('No secrets detected, finish directly.')
        return
    for file_path, secrets in scan_results.items():
        logger.warning(f'Will mask {len(secrets)} secrets for {file_path}')
    if not yes:
        from knack.prompting import prompt_y_n
        if not prompt_y_n(f'Do you want to continue with redaction type {redaction_type}?'):
            return

    if 'raw_data' in scan_results:
        for secret in scan_results['raw_data']:
            data = _mask_secret_for_string(data, secret, redaction_type)
        return data

    for file_path, secrets in scan_results.items():
        with open(file_path, 'r') as f:
            content = f.read()
        if not content:
            continue
        for secret in secrets:
            content = _mask_secret_for_string(content, secret, redaction_type)
        with open(file_path, 'w') as f:
            f.write(content)

