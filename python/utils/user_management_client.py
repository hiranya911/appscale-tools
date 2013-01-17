import socket
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

  def is_port_open(self):
    try:
      sock = socket.socket()
      sock.connect((self.host, 4343))
      return True
    except Exception as exception:
      print exception
      return False

  def create_user(self, username, password, type='xmpp_user'):
    encrypted_pass = commons.sha1_encrypt(username + password)
    try:
      result = self.server.commit_new_user(username, encrypted_pass,
        type, self.secret)
      if result != 'true':
        raise Exception(result)
    except Exception as exception:
      self.__handle_exception(exception)

  def reserve_application_name(self, username, application, language):
    try:
      result = self.server.commit_new_app(application, username,
        language, self.secret)
      if result != 'true':
        raise Exception(result)
    except Exception as exception:
      self.__handle_exception(exception)

  def commit_application_archive(self, application, file_path):
    try:
      result = self.server.commit_tar(application, file_path, self.secret)
      if result != 'true':
        raise Exception(result)
    except Exception as exception:
      self.__handle_exception(exception)

  def set_admin_role(self, username):
    try:
      self.server.set_cloud_admin_status(username, 'true', self.secret)
      self.server.set_capabilities(username, ADMIN_CAPABILITIES, self.secret)
    except Exception as exception:
      self.__handle_exception(exception)

  def __handle_exception(self, exception):
    msg = 'Error while contacting the user manager at '\
          '%s: %s' % (self.host, exception)
    raise AppScaleToolsException(msg)