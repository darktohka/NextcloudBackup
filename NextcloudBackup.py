from EncryptedSettings import EncryptedSettings
from NextcloudDB import NextcloudDB
from CompressUtils import compress_file
from CryptoUtils import derive_key, encrypt_file
from GDrive import GDrive

import json, requests, os, sys, time, hashlib, shutil, traceback, socket

class NextcloudBackup(object):

    def __init__(self):
        self.webhook_url = None
        self.warnings = []

        try:
            self.read_settings()
        except:
            self.complain_and_exit('Could not read settings!')

        try:
            self.read_manifest()
        except:
            self.complain_and_exit('Could not read manifest!')

        try:
            self.connect_to_google()
        except:
            self.complain_and_exit('Could not connect to Google Drive!')

        try:
            nextcloud_files = self.get_nextcloud_files()
        except:
            self.complain_and_exit('Could not contact NextCloud!')

        self.mark_inactive_files(nextcloud_files)
        self.encrypted_folder = self.create_encrypted_folder()

        try:
            self.backup_all(nextcloud_files)
        except:
            self.complain_and_exit('Could not complete backup!')

        if self.warnings:
            self.send_webhook('\n'.join(self.warnings))

    def warn(self, message):
        self.warnings.append(message)
        print(message)

    def send_webhook(self, message, urgent=False):
        if urgent:
            message = '@everyone ' + message

        max_length = 19980

        for message in [message[i:i+max_length] for i in range(0, len(message), max_length)]:
            requests.post(self.webhook_url, headers={'User-Agent': 'Mozilla/5.0'}, data={'content': message})

    def complain_and_exit(self, message):
        exception = traceback.format_exc()

        print(message)
        print(exception)

        if self.webhook_url:
            self.send_webhook('{0}\n```{1}```'.format(message, exception), urgent=True)

        sys.exit()

    def read_settings(self):
        with open('settings.json', 'r') as f:
            self.settings = json.load(f)

        self.file_password = self.settings['file_password']
        self.backup_folder_id = self.settings['backup_folder_id']
        self.nextcloud_username = self.settings['nextcloud_username']
        self.nextcloud_folder = self.settings['nextcloud_folder']
        self.webhook_url = self.settings['webhook_url']

    def read_manifest(self):
        self.manifest = EncryptedSettings('manifest.json', self.settings['manifest_password'])

        if 'lastUpdated' not in self.manifest:
            self.manifest['lastUpdated'] = int(time.time())

        if 'files' not in self.manifest:
            self.manifest['files'] = {}

    def get_nextcloud_files(self):
        nextcloud = NextcloudDB(host=self.settings['mysql_host'], database=self.settings['mysql_db'], user=self.settings['mysql_user'], password=self.settings['mysql_password'])
        nextcloud_conn = nextcloud.get_connection()
        nextcloud_storage_id = nextcloud.get_storage_id(nextcloud_conn, self.nextcloud_username)

        files = nextcloud.get_files(nextcloud_conn, nextcloud_storage_id)
        nextcloud_conn.close()
        return files

    def mark_inactive_files(self, nextcloud_files):
        updatedActive = False

        for filename in list(self.manifest['files'].keys()):
            manifest_file = self.manifest['files'][filename]
            active = filename in nextcloud_files

            if manifest_file['active'] != active:
                print('Setting active for {0}: {1}'.format(filename, active))
                manifest_file['active'] = active
                updatedActive = True

        if updatedActive:
            self.manifest.write()

    def connect_to_google(self):
        self.drive = GDrive(self.settings['team_drive_id'])
        self.drive.connect()

    def create_encrypted_folder(self):
        encrypted_folder = os.path.join(os.getcwd(), 'encrypted')

        if os.path.exists(encrypted_folder):
            shutil.rmtree(encrypted_folder)

        os.makedirs(encrypted_folder)
        return encrypted_folder

    def remove_file_discreetly(self, filename):
        while True:
            try:
                if os.path.exists(filename):
                    os.remove(filename)

                return
            except:
                time.sleep(0.1)

    def backup_file(self, hash_folders, filename, file_info):
        current_version = str(file_info['time'])

        if filename in self.manifest['files']:
            manifest_file = self.manifest['files'][filename]

            if 'versions' in manifest_file and current_version in manifest_file['versions']:
                return False

        drive_path = os.path.join(self.nextcloud_folder, self.nextcloud_username, 'files', filename)

        if not os.path.isfile(drive_path):
            if not os.path.exists(drive_path):
                self.warn('File {0} does not exist!'.format(drive_path))
            else:
                print('File {0} is a folder.'.format(drive_path))

            return False

        if os.path.getsize(drive_path) != file_info['size']:
            self.warn('Size mismatch at {0} between drive ({1}) and database ({2})'.format(drive_path, os.path.getsize(drive_path), file_info['size']))
            return False

        if filename not in self.manifest['files']:
            self.manifest['files'][filename] = {'active': True, 'versions': {}}

        version_hash = hashlib.sha384((filename + current_version).encode('utf-8')).hexdigest()
        hash_folder_name = version_hash[:2]
        hash_folder = self.drive.find_file_in_list(hash_folders, hash_folder_name)

        if not hash_folder:
            hash_folder = self.drive.create_folder(hash_folder_name, self.backup_folder_id)
            hash_folders.append(hash_folder)

        current_drive_file = self.drive.search_for_file(version_hash)

        if current_drive_file:
            self.warn('Hash {0} already exists for file {1}...'.format(version_hash, filename))
            return True

        print('Compressing {0}...'.format(filename))
        version_path = os.path.join(self.encrypted_folder, version_hash)
        compressed_path = version_path + '-compressed'
        compress_file(drive_path, compressed_path)
        compressed_size = os.path.getsize(compressed_path)

        print('Encrypting {0}...'.format(filename))

        encrypted_path = version_path + '-encrypted'
        key = derive_key(self.file_password + version_hash, 32)
        encrypt_file(key, compressed_path, encrypted_path)
        self.remove_file_discreetly(compressed_path)

        print('Uploading {0}...'.format(filename))
        self.drive.upload_file(encrypted_path, hash_folder['id'], version_hash)
        self.manifest['files'][filename]['versions'][current_version] = {'size': file_info['size'], 'encryptedSize': os.path.getsize(encrypted_path), 'compressedSize': compressed_size, 'hash': version_hash}
        self.manifest.write()

        self.remove_file_discreetly(encrypted_path)
        return True

    def backup_all(self, nextcloud_files):
        hash_folders = self.drive.list_folders_in(self.backup_folder_id)
        self.warnings = []
        updated_any = False

        for filename, file_info in nextcloud_files.items():
            if self.backup_file(hash_folders, filename, file_info):
                updated_any = True

        self.manifest.write()

        if updated_any:
            self.upload_manifest(hash_folders)

    def upload_manifest(self, hash_folders):
        manifest_folder = self.drive.find_file_in_list(hash_folders, 'manifests')

        if not manifest_folder:
            manifest_folder = self.drive.create_folder('manifests', self.backup_folder_id)

        print('Uploading manifest...')
        self.drive.upload_file('manifest.json', manifest_folder['id'], 'manifest-{0}.json'.format(time.strftime('%Y%m%d-%H%M%S')))

if __name__ == '__main__':
    def get_lock(process_name):
        get_lock._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

        try:
            get_lock._lock_socket.bind('\0' + process_name)
        except socket.error:
            print('Program is already running!')
            sys.exit()

    if os.geteuid() != 0:
        print('Please run this program as root!')
        sys.exit()

    get_lock('NextcloudBackup')
    NextcloudBackup()
