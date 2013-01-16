import getpass
import os
from time import sleep
import yaml
from utils import commons, cli, cloud
from utils.app_controller_client import AppControllerClient
from utils.commons import AppScaleToolsException
from utils.node_layout import NodeLayout
from utils.user_management_client import UserManagementClient

__author__ = 'hiranya'

APPSCALE_DIR = '~/.appscale'
VERSION = '2.0.0'

class AddKeyPairOptions:
  def __init__(self, ips, keyname, auto=False):
    self.ips = ips
    self.keyname = keyname
    self.auto = auto
    self.root_password = None

class RunInstancesOptions:
  def __init__(self):
    self.infrastructure = None
    self.machine = None
    self.instance_type = None
    self.ips = None
    self.database = None
    self.min = None
    self.max = None
    self.keyname = None
    self.group = None
    self.scp = None
    self.file = None
    self.replication = None
    self.read_q = None
    self.write_q = None
    self.app_engines = None
    self.auto_scale = None
    self.restore_from_tar = None
    self.restore_neptune_info = None
    self.username = None
    self.password = None
    self.testing = None

def add_key_pair(options):
  node_layout = NodeLayout(options.ips)

  required_commands = [ 'ssh-keygen', 'ssh-copy-id' ]
  if options.auto:
    required_commands.append('expect')
  commons.assert_commands_exist(required_commands)

  appscale_dir = os.path.expanduser(APPSCALE_DIR)
  if not os.path.exists(appscale_dir):
    os.mkdir(appscale_dir)
  key_info = commons.generate_rsa_key(appscale_dir, options.keyname)
  pvt_key = key_info[0]
  public_key = key_info[1]

  if options.auto and options.root_password is None:
    options.root_password = getpass.getpass('Enter SSH password of root: ')

  for node in node_layout.nodes:
    commons.ssh_copy_id(node.id, pvt_key, options.auto,
      'sshcopyid', options.root_password)

  head_node = node_layout.get_head_node()
  commons.scp_file(pvt_key, '~/.ssh/id_dsa', head_node.id, pvt_key)
  commons.scp_file(public_key, '~/.ssh/id_rsa.pub', head_node.id, pvt_key)

  print 'A new ssh key has been generated for you and placed at %s. ' \
        'You can now use this key to log into any of the machines you ' \
        'specified without providing a password via the following ' \
        'command:\n    ssh root@%s -i %s' % (pvt_key, head_node.id, pvt_key)

def run_instances(options):
  layout_options = {
    cli.OPTION_INFRASTRUCTURE : options.infrastructure,
    cli.OPTION_DATABASE : options.database,
    cli.OPTION_MIN_IMAGES : options.min,
    cli.OPTION_MAX_IMAGES : options.max,
    cli.OPTION_REPLICATION : options.replication,
    cli.OPTION_READ_FACTOR : options.read_q,
    cli.OPTION_WRITE_FACTOR : options.write_q
  }
  node_layout = NodeLayout(options.ips, layout_options)
  app_info = commons.get_app_info(options.file, options.database)

  appscale_dir = os.path.expanduser(APPSCALE_DIR)
  if not os.path.exists(appscale_dir):
    os.mkdir(appscale_dir)

  if options.infrastructure:
    cloud.validate(options.infrastructure, options.machine)
    print 'Starting AppScale over', options.infrastructure
  else:
    print 'Starting AppScale in a non-cloud environment'

  secret_key_file = os.path.join(APPSCALE_DIR, options.keyname + '.secret')
  secret_key = commons.generate_secret_key(secret_key_file)

  if cloud.is_valid_cloud_type(options.infrastructure):
    cloud.configure_security(options.infrastructure, options.keyname,
      options.group, appscale_dir)
    instance_info = cloud.spawn_head_node(options.infrastructure, options.keyname,
      options.group, options.machine, options.instance_type)
    head_node = instance_info[0]
  else:
    head_node = node_layout.get_head_node()
    instance_info = (head_node.id, head_node.id, 'virtual_node')

  locations = []
  head_node_roles = ':'.join(head_node.roles)
  location = instance_info[0] + ':' + instance_info[1] + \
             ':' + head_node_roles + ':' + instance_info[2]
  locations.append(location)

  named_key_loc = os.path.join(appscale_dir, options.keyname + '.key')
  named_backup_key_loc = os.path.join(appscale_dir, options.keyname + '.private')
  ssh_key = None
  key_exists = False
  for key in (named_key_loc, named_backup_key_loc):
    if os.path.exists(key):
      key_exists = True
      if commons.is_ssh_key_valid(key, head_node.id):
        ssh_key = key
        break

  if not key_exists:
    msg = 'Unable to find a SSH key to login to AppScale nodes'
    raise AppScaleToolsException(msg)
  elif ssh_key is None:
    msg = 'Unable to login to AppScale nodes with the available SSH keys'
    raise AppScaleToolsException(msg)

  location = '/etc/appscale'
  if not commons.remote_location_exists(location, head_node.id, ssh_key):
    msg = 'Failed to locate an AppScale installation in the '\
          'remote instance at', head_node.id
    raise AppScaleToolsException(msg)

  location = '/etc/appscale/%s' % VERSION
  if not commons.remote_location_exists(location, head_node.id, ssh_key):
    msg = 'AppScale version installed at %s is not compatible with '\
          'your version of tools' % head_node.id
    raise AppScaleToolsException(msg)

  location = '/etc/appscale/%s/%s' % (VERSION, options.database)
  if not commons.remote_location_exists(location, head_node.id, ssh_key):
    msg = 'AppScale version installed at %s does not have '\
          'support for %s' % (head_node.id, options.database)
    raise AppScaleToolsException(msg)

  if options.scp is not None:
    commons.copy_appscale_source(options.scp, head_node.id, ssh_key)

  remote_key_file = '/root/.appscale/%s.key' % options.keyname
  commons.scp_file(ssh_key, remote_key_file, head_node.id, ssh_key)

  ips_dict = node_layout.to_dictionary()
  ips_to_use = ''
  for k,v in ips_dict.items():
    if len(ips_to_use) > 0:
      ips_to_use += '..'
    ips_to_use += k + '--' + v

  credentials = {
    'table' : options.database,
    'hostname' : head_node.id,
    'keyname' : options.keyname,
    'keypath' : ssh_key,
    'replication' : node_layout.replication,
    'appengine' : options.app_engines,
    'autoscale' : options.auto_scale,
    'group' : options.group,
    'ips' : ips_to_use
  }
  if options.database == 'voldemort':
    credentials['voldemortr'] = node_layout.read_factor
    credentials['voldemortw'] = node_layout.write_factor
  elif options.database == 'simpledb':
    credentials['SIMPLEDB_ACCESS_KEY'] = os.environ['SIMPLEDB_ACCESS_KEY']
    credentials['SIMPLEDB_SECRET_KEY'] = os.environ['SIMPLEDB_SECRET_KEY']

  if cloud.is_valid_cloud_type(options.infrastructure):
    cloud_credentials = cloud.get_cloud_env_variables(options.infrastructure)
    for key, value in cloud_credentials.items():
      credentials[key] = value

  if options.restore_from_tar:
    db_backup = '/root/db-backup.tar.gz'
    credentials['restore_from_tar'] = db_backup
    commons.scp_file(options.restore_from_tar, db_backup, head_node.id, ssh_key)

  if options.restore_neptune_info:
    neptune_info = '/etc/appscale/neptune_info.txt'
    commons.scp_file(options.restore_neptune_info, neptune_info,
      head_node.id, ssh_key)

  print 'Head node successfully initialized at', head_node.id

  commons.scp_file(secret_key_file, '/etc/appscale/secret.key',
    head_node.id, ssh_key)
  remote_ssh_key_location = '/etc/appscale/ssh.key'
  commons.scp_file(ssh_key, remote_ssh_key_location, head_node.id, ssh_key)

  pk, cert = commons.generate_certificate(appscale_dir, options.keyname)
  commons.scp_file(pk, '/etc/appscale/certs/mykey.pem',
    head_node.id, ssh_key)
  commons.scp_file(cert, '/etc/appscale/certs/mycert.pem',
    head_node.id, ssh_key)

  # TODO: Copy cloud keys

  god_file = '/tmp/controller.god'
  commons.scp_file('utils/resources/controller.god', god_file,
    head_node.id, ssh_key)
  commons.run_remote_command('god &', head_node.id, ssh_key)
  commons.run_remote_command('god load ' + god_file, head_node.id, ssh_key)
  commons.run_remote_command('god start controller', head_node.id, ssh_key)

  client = AppControllerClient(head_node.id, secret_key)
  while not client.is_port_open():
    sleep(2)
  client.set_parameters(locations, commons.map_to_array(credentials),
    app_info[0])

  node_file_path = os.path.join(appscale_dir, 'locations-%s.yaml' % options.keyname)
  node_info = {
    ':load_balancer' : head_node.id,
    ':instance_id' : instance_info[2],
    ':table' : options.database,
    ':shadow' : head_node.id,
    ':secret' : secret_key,
    ':db_master' : node_layout.get_db_master().id,
    ':infrastructure' : options.infrastructure,
    ':group' : options.group,
    ':ips' : client.get_all_public_ips()
  }
  node_file = open(node_file_path, 'w')
  yaml.dump(node_info, node_file, default_flow_style=False)
  node_file.close()
  remote_node_file = '/root/.appscale/locations-%s.yaml' % options.keyname
  commons.scp_file(node_file_path, remote_node_file, head_node.id, ssh_key)

  if options.username is None and options.password is None:
    if options.testing:
      username = os.environ['APPSCALE_USERNAME'] if os.environ.has_key(
        'APPSCALE_USERNAME') else 'a@a.a'
      password = os.environ['APPSCALE_PASSWORD'] if os.environ.has_key(
        'APPSCALE_PASSWORD') else 'aaaaaa'
    else:
      print 'This AppScale instance is linked to an e-mail address giving it' \
            'administrator privileges'
      username, password = commons.prompt_for_user_credentials()
  else:
    print 'Using the provided username and password'
    username = options.username
    password = options.password

  user_manager_host = client.get_user_manager_host()
  user_manager = UserManagementClient(user_manager_host, secret_key)
  while not user_manager.is_port_open():
    print 'Waiting for user manager service'
    sleep(2)
  user_manager.create_user(username, password)
  print 'Created user account for:', username

  login_node = client.get_login_node()
  xmpp_user = username[:username.index('@')] + '@' + login_node
  user_manager.create_user(xmpp_user, password)
  print 'Created XMPP user account for:', xmpp_user

  user_manager.set_admin_role(username)
  print 'Admin privileges granted to:', username

  # TODO: Wait for nodes to start

  if app_info[0] is None:
    print 'No application was specified for deployment. You can later upload' \
          'an application using the appscale-upload-app command'
  else:
    # TODO: Upload application
    while not client.is_app_running(app_info[0]):
      sleep(5)
    app_url = 'http://%s/apps/%s' % (head_node.id, app_info[0])
    print 'Your app can be reached at', app_url

  login_url = 'http://%s/status' % login_node
  print 'The status of your AppScale instance can be found at', login_url

  # TODO: Write node file

