import SOAPpy
from utils import commons
from utils.commons import AppScaleToolsException

__author__ = 'hiranya'

ADMIN_CAPABILITIES = ":".join(["upload_app", "mr_api", "ec2_api", "neptune_api"])

class UserManagementClient:
  def __init__(self, host, secret):
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:4343' % host)
    self.secret = secret

  def create_user(self, username, password, type='xmpp_user'):
    encrypted_pass = commons.sha1_encrypt(username + password)
    try:
      result = self.server.commit_new_user(username, encrypted_pass,
        type, self.secret)
      if result != 'true':
        raise Exception('Unexpected response from the user '
                        'management service: ' + result)
    except Exception as exception:
      self.__handle_exception(exception)

  def set_admin_role(self, username):
    try:
      self.server.set_cloud_admin_status(username, True, self.secret)
      self.server.set_capabilities(username, ADMIN_CAPABILITIES)
    except Exception as exception:
      self.__handle_exception(exception)

  def __handle_exception(self, exception):
    msg = 'Error while contacting the user manager at '\
          '%s: %s' % (self.host, exception)
    raise AppScaleToolsException(msg)