from contextlib import closing
from .CompressUtils import check_patterns
import fnmatch
import mysql.connector

class NextcloudDB(object):

    def __init__(self, host, database, user, password):
        self.host = host
        self.database = database
        self.user = user
        self.password = password

    def get_connection(self):
        connection = mysql.connector.connect(host=self.host, database=self.database, user=self.user, password=self.password)

        if not connection.is_connected():
            raise Exception('MySQL connection failed!')

        return connection

    def fetch_all(self, connection, query, parameters):
        with closing(connection.cursor(buffered=True)) as cursor:
            cursor.execute(query, parameters)
            return cursor.fetchall()

    def fetch(self, connection, query, parameters):
        with closing(connection.cursor(buffered=True)) as cursor:
            cursor.execute(query, parameters)
            return cursor.fetchone()

    def get_storage_id(self, connection, username):
        storage_id = self.fetch(connection, "select numeric_id from oc_storages where id=%s", ('home::{0}'.format(username),))

        if not storage_id:
            raise Exception('Storage ID not found for user {0}!'.format(username))

        return storage_id[0]

    def get_files(self, connection, storage_id, ignore=None, limit=0):
        query = "select path, storage_mtime from oc_filecache where storage=%s and mimetype != 2 and mimepart != 1 and path like 'files/%'"

        if limit > 0:
            query += ' limit {0}'.format(limit)

        files = self.fetch_all(connection, query, (storage_id,))
        all_files = {}

        for file in files:
            filename, time = file
            filename = filename[len('files/'):]

            if not check_patterns(filename, ignore):
                all_files[filename] = int(time)

        return all_files
