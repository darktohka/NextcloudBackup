
from .EncryptedSettings import EncryptedSettings
from .NextcloudDB import NextcloudDB
from .CompressUtils import compress_file, check_patterns
from .CryptoUtils import derive_key, encrypt_file
from .GDrive import GDrive
from .OneDrive import OneDrive

from pydrive.files import ApiRequestError
from googleapiclient.errors import HttpError
from queue import Queue

import builtins
import argparse, atexit, json, requests, os, sys, time, hashlib, shutil, threading, traceback, socket

class BackupThread(threading.Thread):

    def __init__(self, base):
        threading.Thread.__init__(self)
        self.daemon = True
        self.base = base
        self.timeout = 0

    def run(self):
        while True:
            if self.timeout:
                time.sleep(self.timeout)
                self.timeout = 0

            server_name, filename = self.base.queue.get()
            server = self.base.get_server(server_name)

            try:
                server.backup_file(filename)
            except (ApiRequestError, HttpError) as e:
                if 'HttpError' in str(e):
                    self.base.queue.put([server_name, filename])
                    self.base.signal_api_timeout()
                    continue

                self.base.complain_and_exit('Could not upload file {0}!'.format(filename))
            except:
                self.base.complain_and_exit('Could not upload file {0}!'.format(filename))
            finally:
                self.base.queue.task_done()

class VerifyThread(threading.Thread):

    def __init__(self, base):
        threading.Thread.__init__(self)
        self.daemon = True
        self.base = base
        self.timeout = 0

    def run(self):
        while True:
            if self.timeout:
                time.sleep(self.timeout)
                self.timeout = 0

            server_name, folder_name, folder_id = self.base.queue.get()
            server = self.base.get_server(server_name)
            files = []

            try:
                files = server.drive.list_files_in(folder_id)
            except (ApiRequestError, HttpError) as e:
                if 'HttpError' in str(e):
                    self.base.queue.put([server_name, folder_name, folder_id])
                    self.base.signal_api_timeout()
                    continue

                self.base.complain_and_exit('Could not list folder {0}!'.format(folder_name))
            except:
                self.base.complain_and_exit('Could not list folder {0}!'.format(folder_name))
            finally:
                self.base.queue.task_done()

            server.folder_lock.acquire()

            for file in files:
                server.folders[folder_name][file['title']] = int(file['fileSize'])

            server.folder_lock.release()

class ServerBackup(object):

    def __init__(self, base, name, settings):
        self.base = base
        self.name = name
        self.settings = settings
        self.manifest_changed = 0
        self.should_update_manifest = False
        self.manifest_lock = threading.Lock()
        self.drives = []

        self.file_password = self.settings['file_password']
        self.base_folder = self.get_base_folder()

    def get_files(self):
        return NotImplementedError('To be implemented')

    def get_base_folder(self):
        return NotImplementedError('To be implemented')

    def get_manifest_filename(self):
        return os.path.join(self.base.manifest_folder, '{0}.json'.format(self.name))

    def initialize(self):
        try:
            self.read_manifest()
        except:
            self.base.complain_and_exit('Could not read manifest for {0}!'.format(self.name))

        for drive in self.settings['drives']:
            if drive['type'] == 'google':
                drive = GDrive(drive)
            elif drive['type'] == 'onedrive':
                drive = OneDrive(drive)
            else:
                raise Exception('Unknown drive type: {0}'.format(drive['type']))

            try:
                drive.connect()
            except:
                self.base.complain_and_exit('Could not connect to {0}!'.format(drive.get_name()))

            self.drives.append(drive)

    def initialize_files(self):
        try:
            self.all_files = self.get_files()
        except:
            self.base.complain_and_exit('Could not enumerate file list!')

        self.mark_inactive_files()

    def queue_all(self):
        for filename in self.all_files:
            self.base.queue.put([self.name, filename])

    def queue_verify_all(self):
        self.folders = {}
        self.folder_lock = threading.Lock()

        for folder in self.hash_folders:
            name = folder['title']
            self.folders[name] = {}

            if name != 'manifests':
                self.base.queue.put([self.name, name, folder['id']])

    def manifest_updated(self):
        self.manifest_lock.acquire()
        self.manifest_changed += 1
        self.should_update_manifest = True

        if self.manifest_changed == 100:
            self.manifest.write()
            self.manifest_changed = 0

        self.manifest_lock.release()

    def write_manifest(self):
        self.manifest_lock.acquire()

        try:
            self.manifest.write()
        finally:
            self.manifest_changed = 0
            self.manifest_lock.release()

    def read_manifest(self):
        self.manifest = EncryptedSettings(self.get_manifest_filename(), self.settings['manifest_password'])

        if 'lastUpdated' not in self.manifest:
            self.manifest['lastUpdated'] = int(time.time())

        if 'files' not in self.manifest:
            self.manifest['files'] = {}

    def check_integrity(self):
        for filename, file in self.manifest['files'].items():
            for version_name, version in file['versions'].items():
                hash = version['hash']
                hash_folder = hash[:2]

                if hash_folder not in self.folders:
                    self.base.warn('Could not find hash folder {0} for file {1} (version {2})!'.format(hash_folder, filename, version_name))
                    continue
                if hash not in self.folders[hash_folder]:
                    self.base.warn('Could not find hash file {0} for file {1} (version {2})!'.format(hash, filename, version_name))
                    continue

                actual_size = self.folders[hash_folder][hash]
                expected_size = int(version['encryptedSize'])

                if actual_size != expected_size:
                    self.base.warn('Hash file {0} for file {1} (version {2}) has unexpected size. Expected {3} bytes, got {4} bytes.'.format(hash, filename, version_name, expected_size, actual_size))
                    continue

    def mark_inactive_files(self):
        always_active = self.settings.get('always_active')

        for filename, file in self.manifest['files'].items():
            active = filename in self.all_files or check_patterns(filename, always_active)

            if file['active'] != active:
                print('Setting active for {0}: {1}'.format(filename, active))
                file['active'] = active
                self.should_update_manifest = True

    def backup_file(self, filename):
        file_info = self.all_files[filename]
        current_version = str(file_info['time'])

        # Check if the file is already in the manifest
        if filename in self.manifest['files']:
            manifest_file = self.manifest['files'][filename]

            # The file is in the manifest. Do we have the latest version?
            if 'versions' in manifest_file and current_version in manifest_file['versions']:
                return False

        # We don't have the latest version! Let's upload it.
        drive_path = os.path.join(self.base_folder, filename)

        # The file does not exist!
        if not os.path.isfile(drive_path):
            if not os.path.exists(drive_path):
                self.base.warn('File {0} does not exist!'.format(drive_path))

            return False

        if os.path.getsize(drive_path) != file_info['size']:
            # There is a mismatch between the database and the actual drive.
            self.base.warn('Size mismatch at {0} between drive ({1}) and database ({2})'.format(drive_path, os.path.getsize(drive_path), file_info['size']))
            return False

        if filename not in self.manifest['files']:
            self.manifest['files'][filename] = {'active': True, 'versions': {}}
            self.manifest_updated()

        version_hash = hashlib.sha384((filename + current_version).encode('utf-8')).hexdigest()
        exists = False

        # TODO: Instead of "exists" variable we should use a different approach...
        for drive in self.drives:
            hash_folder_name = version_hash[:2]
            hash_folder = drive.find_file_in_root(hash_folder_name)

            if not hash_folder:
                hash_folder = drive.create_folder_in_root(hash_folder_name)

            current_drive_file = drive.search_for_file_in(hash_folder['id'], version_hash)

            if current_drive_file:
                file_size = drive.get_file_size(current_drive_file)
                self.base.warn('Hash {0} already exists for file {1}...'.format(version_hash, filename))

                if file_size > 0:
                    self.manifest['files'][filename]['versions'][current_version] = {'size': file_info['size'], 'encryptedSize': file_size, 'hash': version_hash}
                    self.manifest_updated()
                else:
                    self.base.warn('Hash {0} exists for file {1} but has a bad file size.'.format(version_hash, filename))

                exists = True

        if exists:
            return True

        print('Compressing {0}...'.format(filename))
        version_path = os.path.join(self.base.encrypted_folder, version_hash)
        compressed_path = version_path + '-compressed'
        compress_file(drive_path, compressed_path)

        print('Encrypting {0}...'.format(filename))

        encrypted_path = version_path + '-encrypted'
        key = derive_key(self.file_password + version_hash, 32)
        encrypt_file(compressed_path, encrypted_path, filename, timestamp=int(float(current_version)), key=key)
        self.base.remove_file_discreetly(compressed_path)

        print('Uploading {0}...'.format(filename))
        for drive in self.drives:
            drive.upload_file(source_filename=encrypted_path, folder_id=hash_folder['id'], filename=version_hash)
            self.manifest['files'][filename]['versions'][current_version] = {'size': file_info['size'], 'encryptedSize': os.path.getsize(encrypted_path), 'hash': version_hash}
            self.manifest_updated()

        self.base.remove_file_discreetly(encrypted_path)
        return True

    def upload_manifest_if_needed(self):
        if self.should_update_manifest:
            try:
                self.write_manifest()

                for drive in self.drives:
                    self.upload_manifest(drive)
            except:
                self.base.complain_and_exit('Could not upload manifest!')

    def upload_manifest(self, drive):
        manifest_folder = drive.find_file_in_root('manifests')

        if not manifest_folder:
            manifest_folder = drive.create_folder_in_root('manifests')

        print('Uploading manifest...')
        drive.upload_file(self.get_manifest_filename(), manifest_folder['id'], 'manifest-{0}.json'.format(time.strftime('%Y%m%d-%H%M%S')))

class NextcloudServer(ServerBackup):

    def get_files(self):
        nextcloud = NextcloudDB(host=self.settings['mysql_host'], database=self.settings['mysql_db'], user=self.settings['mysql_user'], password=self.settings['mysql_password'])
        nextcloud_conn = nextcloud.get_connection()
        nextcloud_storage_id = nextcloud.get_storage_id(nextcloud_conn, self.settings['nextcloud_username'])

        files = nextcloud.get_files(nextcloud_conn, nextcloud_storage_id, self.settings.get('ignore'))
        nextcloud_conn.close()
        return files

    def get_base_folder(self):
        return os.path.join(self.settings['nextcloud_folder'], self.settings['nextcloud_username'], 'files')

class FilesystemServer(ServerBackup):

    def get_files(self):
        all_files = {}
        base_folder = self.get_base_folder()
        ignore = self.settings.get('ignore')

        for root, _, files in os.walk(base_folder):
            short_root = root[len(base_folder) + 1:]

            for file in files:
                short_filename = os.path.join(short_root, file)

                if check_patterns(short_filename, ignore):
                    continue

                filename = os.path.join(root, file)
                all_files[short_filename] = {'size': os.path.getsize(filename), 'time': os.path.getmtime(filename)}

        return all_files

    def get_base_folder(self):
        return self.settings['folder']

class NextcloudBackup(object):

    def __init__(self):
        self.webhook_url = None
        self.warnings = []
        self.queue = Queue()
        self.servers = {}
        self.threads = []
        self.encrypted_folder = self.create_encrypted_folder()
        self.manifest_folder = self.create_manifest_folder()

    def initialize(self):
        try:
            self.read_settings()
        except:
            self.complain_and_exit('Could not read settings!')

        for name, settings in self.settings['backups'].items():
            if not settings.get('enabled', True):
                continue

            type = settings['type']

            if type == 'nextcloud':
                server = NextcloudServer(self, name, settings)
            elif type == 'filesystem':
                server = FilesystemServer(self, name, settings)
            else:
                raise Exception('Invalid type specified!')

            self.servers[name] = server
            server.initialize()

    def backup_all_servers(self):
        for server in self.servers.values():
            server.initialize_files()
            server.queue_all()

        self.start_backup_threads()

    def verify_all_servers(self):
        for server in self.servers.values():
            server.queue_verify_all()

        self.start_verify_threads()

    def get_server(self, name):
        return self.servers.get(name)

    def send_warnings(self):
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

        self.send_warnings()
        sys.exit()

    def read_settings(self):
        with open('settings.json', 'r') as f:
            self.settings = json.load(f)

        self.webhook_url = self.settings['webhook_url']

    def write_settings(self):
        with open('settings.json', 'w') as f:
            json.dump(self.settings, f, sort_keys=True, indent=2, separators=(',', ': '))

    def create_encrypted_folder(self):
        encrypted_folder = os.path.join(os.getcwd(), 'encrypted')

        if os.path.exists(encrypted_folder):
            shutil.rmtree(encrypted_folder)

        os.makedirs(encrypted_folder)
        return encrypted_folder

    def create_manifest_folder(self):
        manifest_folder = os.path.join(os.getcwd(), 'manifests')

        if not os.path.exists(manifest_folder):
            os.makedirs(manifest_folder)

        return manifest_folder

    def remove_file_discreetly(self, filename):
        while True:
            try:
                if os.path.exists(filename):
                    os.remove(filename)

                return
            except:
                time.sleep(0.1)

    def create_threads(self, thread_class, count):
        self.threads = []

        for i in range(count):
            thread = thread_class(self)
            thread.start()
            self.threads.append(thread)

    def start_backup_threads(self):
        atexit.register(self.write_all_manifests)

        if not self.queue.empty():
            self.create_threads(BackupThread, count=5)
            self.queue.join()

        self.send_warnings()

        for server in self.servers.values():
            server.upload_manifest_if_needed()

    def start_verify_threads(self):
        if not self.queue.empty():
            print('Downloading file list...')
            self.create_threads(VerifyThread, count=3)
            self.queue.join()

        print('Verifying integrity...')

        for server in self.servers.values():
            server.check_integrity()

        print('Integrity verification complete.')
        self.send_warnings()

    def write_all_manifests(self):
        for server in self.servers.values():
            if server.should_update_manifest:
                server.write_manifest()

    def signal_api_timeout(self):
        signal = False

        for thread in self.threads:
            if thread.timeout != 45:
                thread.timeout = 45
                signal = True

        if signal:
            print('API timeout! Waiting for 45 seconds...')

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

    parser = argparse.ArgumentParser(description='Backup Nextcloud to Google Drive.')
    parser.add_argument('--integrity', '-i', action='store_true')
    args = parser.parse_args()

    if args.integrity:
        get_lock('NextcloudBackupIntegrity')
    else:
        get_lock('NextcloudBackup')

    builtins.base = NextcloudBackup()
    base.initialize()

    if args.integrity:
        base.verify_all_servers()
    else:
        base.backup_all_servers()
