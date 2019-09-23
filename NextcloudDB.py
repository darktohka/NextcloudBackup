from contextlib import closing
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
    
    def get_files(self, connection, storage_id, limit=0):
        query = "select path, size, storage_mtime from oc_filecache where storage=%s and path like 'files/%'"

        if limit > 0:
            query += ' limit {0}'.format(limit)

        files = self.fetch_all(connection, query, (storage_id,))
        files = {file[0][len('files/'):]: {'size': file[1], 'time': file[2]} for file in files}
        return files