#!/usr/bin/env python
# Programmer: Chris Bunch (chris@appscale.com)


# General-purpose Python library imports
import base64
import os
import shutil
import subprocess
import sys
import unittest
import yaml


# Third party testing libraries
from flexmock import flexmock


# AppScale import, the library that we're testing here
lib = os.path.dirname(__file__) + os.sep + ".." + os.sep + "lib"
sys.path.append(lib)
from appscale import AppScale
from custom_exceptions import AppScalefileException
from custom_exceptions import BadConfigurationException
from custom_exceptions import UsageException


class TestAppScale(unittest.TestCase):


  def setUp(self):
    pass

  
  def tearDown(self):
    pass


  def testReportHelp(self):
    # calling 'appscale help' should report usage information
    appscale = AppScale()
    self.assertRaises(UsageException, appscale.help)


  def testInitWithNoAppScalefile(self):
    # calling 'appscale init cloud' if there's no AppScalefile in the local
    # directory should write a new cloud config file there
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' + appscale.APPSCALEFILE).and_return(False).once()

    # mock out the actual writing of the template file
    flexmock(shutil)
    shutil.should_receive('copy').with_args(appscale.TEMPLATE_CLOUD_APPSCALEFILE, '/boo/' + appscale.APPSCALEFILE).and_return().once()

    appscale.init('cloud')


  def testInitWithAppScalefile(self):
    # calling 'appscale init cloud' if there is an AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    flexmock(os.path)
    os.path.should_receive('exists').with_args('/boo/' + appscale.APPSCALEFILE).and_return(True).once()

    self.assertRaises(AppScalefileException, appscale.init, 'cloud')


  def testUpWithNoAppScalefile(self):
    # calling 'appscale up' if there is no AppScalefile present
    # should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))

    self.assertRaises(AppScalefileException, appscale.up)


  def testUpWithClusterAppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should call appscale-run-instances with the given config
    # params. here, we assume that the file is intended for use
    # on a virtualized cluster
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'ips_layout': {'master': 'ip1', 'appengine': 'ip1',
                     'database': 'ip2', 'zookeeper': 'ip2'},
      'keyname': 'boobazblarg'
    }
    yaml_dumped_contents = yaml.dump(contents)
    base64_ips_layout = base64.b64encode(yaml.dump(contents["ips_layout"]))

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
     .with_args('/boo/' + appscale.APPSCALEFILE)
     .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # for this test, let's say that we don't have an SSH key already
    # set up for ip1 and ip2
    # TODO(cgb): Add in tests where we have a key for ip1 but not ip2,
    # and the case where we have a key but it doesn't work
    flexmock(os.path)
    key_path = os.path.expanduser('~/.appscale/boobazblarg.key')
    os.path.should_receive('exists').with_args(key_path).and_return(False).once()


    # finally, mock out the actual appscale tools calls. since we're running
    # via a cluster, this means we call add-keypair to set up SSH keys, then
    # run-instances to start appscale
    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["appscale-add-keypair",
                                                 "--keyname",
                                                 "boobazblarg",
                                                 "--ips_layout",
                                                 base64_ips_layout]).and_return().once()
    subprocess.should_receive('call').with_args(["appscale-run-instances",
                                                 "--ips_layout",
                                                 base64_ips_layout,
                                                 "--keyname",
                                                 "boobazblarg",
                                                 ]).and_return().once()
    appscale.up()


  def testUpWithCloudAppScalefile(self):
    # calling 'appscale up' if there is an AppScalefile present
    # should call appscale-run-instances with the given config
    # params. here, we assume that the file is intended for use
    # on EC2
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-run-instances call
    # TODO(cgb): find a better way to do this
    flexmock(subprocess)
    subprocess.should_receive('call').and_return().once()
    appscale.up()


  def testStatusWithNoAppScalefile(self):
    # calling 'appscale status' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))

    self.assertRaises(AppScalefileException, appscale.status)


  def testStatusWithCloudAppScalefile(self):
    # calling 'appscale status' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-describe-instances' command and then exec it
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-run-instances call
    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["appscale-describe-instances", "--keyname", "bookey"]).and_return().once()
    appscale.status()


  def testDeployWithNoAppScalefile(self):
    # calling 'appscale deploy' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))

    app = "/bar/app"
    self.assertRaises(AppScalefileException, appscale.deploy, app)


  def testDeployWithCloudAppScalefile(self):
    # calling 'appscale deploy app' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-upload-app' command and then exec it
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-run-instances call
    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["appscale-upload-app", "--keyname", "bookey", "--file", "/bar/app"]).and_return().once()
    app = '/bar/app'
    appscale.deploy(app)


  def testDeployWithCloudAppScalefileAndTestFlag(self):
    # same as before, but with the 'test' flag in our AppScalefile
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1,
      'test' : True
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-run-instances call
    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["appscale-upload-app", "--keyname", "bookey", "--test", "--file", "/bar/app"]).and_return().once()
    app = '/bar/app'
    appscale.deploy(app)


  def testDestroyWithNoAppScalefile(self):
    # calling 'appscale destroy' with no AppScalefile in the local
    # directory should throw up and die
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_raise(IOError))

    self.assertRaises(AppScalefileException, appscale.destroy)


  def testDestroyWithCloudAppScalefile(self):
    # calling 'appscale destroy' with an AppScalefile in the local
    # directory should collect any parameters needed for the
    # 'appscale-terminate-instances' command and then exec it
    appscale = AppScale()

    flexmock(os)
    os.should_receive('getcwd').and_return('/boo').once()

    # Mock out the actual file reading itself, and slip in a YAML-dumped
    # file
    contents = {
      'infrastructure' : 'ec2',
      'machine' : 'ami-ABCDEFG',
      'keyname' : 'bookey',
      'group' : 'boogroup',
      'verbose' : True,
      'min' : 1,
      'max' : 1
    }
    yaml_dumped_contents = yaml.dump(contents)

    mock = flexmock(sys.modules['__builtin__'])
    mock.should_call('open')  # set the fall-through
    (mock.should_receive('open')
      .with_args('/boo/' + appscale.APPSCALEFILE)
      .and_return(flexmock(read=lambda: yaml_dumped_contents)))

    # finally, mock out the actual appscale-terminate-instances call
    flexmock(subprocess)
    subprocess.should_receive('call').with_args(["appscale-terminate-instances", "--keyname", "bookey"]).and_return().once()
    appscale.destroy()