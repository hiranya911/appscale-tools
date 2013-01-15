import socket
import SOAPpy
from utils.commons import AppScaleToolsException

__author__ = 'hiranya'

class AppControllerClient:

  def __init__(self, host, secret):
    self.host = host
    self.server = SOAPpy.SOAPProxy('https://%s:17443' % host)
    self.secret = secret

  def is_port_open(self):
    try:
      sock = socket.socket()
      sock.connect((self.host, 17443))
      return True
    except Exception as exception:
      print exception
      return False

  def is_live(self):
    try:
      self.server.status(self.secret)
      return True
    except Exception:
      return False

  def set_parameters(self, locations, credentials, app):
    try:
      if app is None:
        app = 'none'
      result = self.server.set_parameters(locations, credentials,
        app, self.secret)
      if result.startswith('Error'):
        raise Exception(result)
    except Exception as exception:
      self.__handle_exception(exception)

  def is_app_running(self, app):
    try:
      return self.server.is_app_running(app, self.secret)
    except Exception:
      return False

  def get_all_public_ips(self):
    try:
      return self.get_all_public_ips()
    except Exception as exception:
      self.__handle_exception(exception)

  def get_status(self):
    try:
      return self.status(self.secret)
    except Exception as exception:
      self.__handle_exception(exception)

  def __handle_exception(self, exception):
    msg = 'Error while contacting the AppController at ' \
          '%s: %s' % (self.host, exception)
    raise AppScaleToolsException(msg)
