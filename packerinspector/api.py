# -*- coding: utf-8 -*-
"""
Module to interact with Deep Packer Inspector's API.
See https://www.packerinspector.com/reference#dpi-api-v1
"""
import os
import requests


class PublicAPI(object):
    """
    Class to interact with DPI's Public API v1.0
    """
    MAX_SAMPLE_SIZE_BYTES = 8 * 1024 * 1024
    MAX_SAMPLE_SIZE_STR = '8MB'
    URL = 'https://www.packerinspector.com/dpiapi/v1/'

    FILE_SIZE_ERROR = 'You exceed the maximum file size (' + \
                      MAX_SAMPLE_SIZE_STR + ').'
    AUX_NOT_FOUND_ERROR = 'Auxiliary file {} not found.'

    def __init__(self, api_key):
        self.api_key = api_key
        if not self.api_key or len(self.api_key) != 64:
            raise APIException('Invalid Deep Packer Inspector API key.')

    def scan_sample(self, sample_path, private, *aux_files):
        """
        Scans a sample.
        See https://www.packerinspector.com/reference#v1-scan

        :param sample_path: path to the sample (main file).
        :param private: whether the scan is private or not.
        :param *aux_files: path/s to the auxiliary file/s (e.g. dlls).
        :return: JSON response with status, dpicode, description, id and
        upload_sha256.
        """
        if not os.path.isfile(sample_path):
            raise APIException('Main file not found.')
        main_size = os.stat(sample_path).st_size
        if main_size > PublicAPI.MAX_SAMPLE_SIZE_BYTES:
            raise APIException(PublicAPI.FILE_SIZE_ERROR)
        tot_size = main_size

        form = {'api-key': self.api_key, 'private': 'Yes' if private else 'No'}
        files = [('main-file', open(sample_path, 'rb'))]
        for aux, pos in zip(list(aux_files), range(len(aux_files))):
            if not os.path.isfile(aux):
                raise APIException(PublicAPI.AUX_NOT_FOUND_ERROR.format(aux))
            tot_size += os.stat(aux).st_size
            if tot_size > PublicAPI.MAX_SAMPLE_SIZE_BYTES:
                raise APIException(PublicAPI.FILE_SIZE_ERROR)
            files.append(('extra-' + str(pos), open(aux, 'rb')))

        try:
            response = requests.post(PublicAPI.URL + 'scan', data=form,
                                     files=files)
            return response.json()
        except requests.RequestException as ex:
            raise APIException('Error with the request: {}'.format(str(ex)))

    def rescan_sample(self, sample_path, *aux_files):
        """
        Re-scans a sample (sends a sample as private to force its scan).

        :param sample_path: path to the sample
        :param *aux_files: path/s to the auxiliary file/s.
        :return: JSON response with status, dpicode, description, id and
        upload_sha256.
        """
        return self.scan_sample(sample_path, True, *aux_files)

    def get_report(self, report_id, get_static_pe_info=True,
                   get_vt_scans=True):
        """
        Returns the results of a report given its id. The id is given as a
        JSON response in the scan_sample method (/scan endpoint).
        See https://www.packerinspector.com/reference#v1-report

        :param report_id: id of the report.
        :param get_static_pe_info: whether we want to retrieve the static PE
        info or not, True by default.
        :param get_vt_scans: whether we want to retrieve VT's scans, True by
        default.
        :return: JSON response with status, dpicode, description, id,
        report-url, file-identification, packer-analysis,
        static-pe-information, vt-scans and report.
        """
        if not report_id:
            raise APIException('Invalid report ID')
        params = {'api-key': self.api_key,
                  'get-vt-scans': 'Yes' if get_vt_scans else 'No',
                  'get-static-pe-info': 'Yes' if get_static_pe_info else 'No'}
        try:
            response = requests.get(PublicAPI.URL + 'report/' + report_id,
                                    params=params)
            return response.json()
        except requests.RequestException as ex:
            raise APIException('Error with the request: {}'.format(str(ex)))

    def get_memory_dump(self, report_id, dest_folder=None):
        """
        Returns the memory dump of a report given its id.
        See https://www.packerinspector.com/reference#v1-memorydump

        :param report_id: id of the report.
        :param dest_folder: folder where the memory dump will be saved, the
        memory dump will have the name of the report id. A tar.gz is saved.
        If no path is specified this method will return the raw content.
        :return: None if the memory dump could be retrieved and saved given a
        dest_folder. Raw content if the memory dump could be retrieved but no
        dest_folder was specified.
        JSON with status, dpicode, description (optionally flag if you have
        raised an API red flag) if the memory dump could not be retrieved.
        """
        if not report_id:
            raise APIException('Invalid report ID')
        try:
            response = requests.get(PublicAPI.URL + 'memorydump/' + report_id,
                                    params={'api-key': self.api_key})
            if response.headers.get('Content-Type') == 'application/x-tar':
                if not dest_folder:
                    return response.content
                with open(os.path.join(dest_folder, report_id + '.tar.gz'),
                          'wb') as tar:
                    for block in response.iter_content(1024):
                        tar.write(block)
            elif response.headers.get('Content-Type') == 'application/json':
                return response.json()
            else:
                raise APIException('Cannot handle response: {}'.format(
                    str(response.content)))
        except requests.RequestException as ex:
            raise APIException('Error with the request: {}'.format(str(ex)))

    def get_unpacking_graph(self, report_id, dest_folder=None):
        """
        Returns the unpacking graph image given its report id.
        See https://www.packerinspector.com/reference#v1-graph

        :param report_id: id of the report.
        :param dest_folder: folder where the unpacking graph will be saved,
        the graph will have the name of the report id. A png is saved.
        If no path is specified this method will return the raw content.
        :return: None if the graph could be retrieved and saved given a
        dest_folder. Raw content if the graph could be retrieved but no
        dest_folder was specified.
        JSON with status, dpicode, description (optionally flag if you have
        raised an API red flag) if the graph could not be retrieved.
        """
        if not report_id:
            raise APIException('Invalid report ID.')
        try:
            response = requests.get(PublicAPI.URL + 'graph/' + report_id,
                                    params={'api-key': self.api_key})
            if response.headers.get('Content-Type') == 'image/png':
                if not dest_folder:
                    return response.content
                with open(os.path.join(dest_folder, report_id + '.png'),
                          'wb') as img:
                    for block in response.iter_content(1024):
                        img.write(block)
            elif response.headers.get('Content-Type') == 'application/json':
                return response.json()
            else:
                raise APIException('Cannot handle response: {}'.format(
                    str(response.content)))
        except requests.RequestException as ex:
            raise APIException('Error with the request: {}'.format(str(ex)))


class APIException(Exception):
    """Encapsulates the API exceptions."""
    pass
