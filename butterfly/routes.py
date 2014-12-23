# *-* coding: utf-8 *-*
# This file is part of butterfly
#
# butterfly Copyright (C) 2014  Florian Mounier
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import pty
import os
import io
import struct
import fcntl
import termios
import tornado.web
import tornado.websocket
import tornado.process
import tornado.ioloop
import tornado.options
import sys
import signal
import base64
from butterfly import url, Route, utils, __version__

ioloop = tornado.ioloop.IOLoop.instance()

server = utils.User()
daemon = utils.User(name='daemon')

# Python 2 backward compatibility
try:
    input = raw_input
except NameError:
    pass


def u(s):
    if sys.version_info[0] == 2:
        return s.decode('utf-8')
    return s


def motd(socket):
    return (
'''
B                   `         '
   ;,,,             `       '             ,,,;
   `Y888888bo.       :     :       .od888888Y'
     8888888888b.     :   :     .d8888888888
     88888Y'  `Y8b.   `   '   .d8Y'  `Y88888
    j88888  R.db.B  Yb. '   ' .dY  R.db.B  88888k
      `888  RY88YB    `b ( ) d'    RY88YB  888'
       888b  R'"B        ,',        R"'B  d888
      j888888bd8gf"'   ':'   `"?g8bd888888k
        R'Y'B   .8'     d' 'b     '8.   R'Y'X
         R!B   .8' RdbB  d'; ;`b  RdbB '8.   R!B
            d88  R`'B  8 ; ; 8  R`'B  88b             Rbutterfly Zv %sB
           d888b   .g8 ',' 8g.   d888b
          :888888888Y'     'Y888888888:           AConnecting to:B
          '! 8888888'       `8888888 !'              G%sB
             '8Y  R`Y         Y'B  Y8'
R              Y                   Y               AFrom:R
              !                   !                  G%sX

'''
        .replace('G', '\x1b[3%d;1m' % (
            1 if tornado.options.options.unsecure else 2))
        .replace('B', '\x1b[34;1m')
        .replace('R', '\x1b[37;1m')
        .replace('Z', '\x1b[33;1m')
        .replace('A', '\x1b[37;0m')
        .replace('X', '\x1b[0m')
        .replace('\n', '\r\n')
        % (__version__,
           '%s:%d' % (socket.local_addr, socket.local_port),
           '%s:%d' % (socket.remote_addr, socket.remote_port)))

def senseMotd(socket):
    return "Welcome to your Sense console terminal.\r\n"

# Cribbed from http://kevinsayscode.tumblr.com/post/7362319243/easy-basic-http-authentication-with-tornado
def require_basic_auth(handler_class):
    # Should return the new _execute function, one which enforces
    # authentication and only calls the inner handler's _execute() if
    # it's present.
    def wrap_execute(handler_execute):
        # I've pulled this out just for clarity, but you could stick
        # it in _execute if you wanted.  It returns True iff
        # credentials were provided.  (The end of this function might
        # be a good place to see if you like their username and
        # password.)
        def require_basic_auth(handler, kwargs):
            auth_header = handler.request.headers.get('Authorization')
            if auth_header is None or not auth_header.startswith('Basic '):
                # If the browser didn't send us authorization headers,
                # send back a response letting it know that we'd like
                # a username and password (the "Basic" authentication
                # method).  Without this, even if you visit put a
                # username and password in the URL, the browser won't
                # send it.  The "realm" option in the header is the
                # name that appears in the dialog that pops up in your
                # browser.
                handler.set_status(401)
                handler.set_header('WWW-Authenticate', 'Basic realm=Restricted')
                handler._transforms = []
                handler.finish()
                return False
            # The information that the browser sends us is
            # base64-encoded, and in the format "username:password".
            # Keep in mind that either username or password could
            # still be unset, and that you should check to make sure
            # they reflect valid credentials!
            auth_decoded = base64.decodestring(auth_header[6:])
            username, password = auth_decoded.split(':', 2)
            kwargs['basicauth_user'], kwargs['basicauth_pass'] = username, password
            return True

        # Since we're going to attach this to a RequestHandler class,
        # the first argument will wind up being a reference to an
        # instance of that class.
        def _execute(self, transforms, *args, **kwargs):
            if not require_basic_auth(self, kwargs):
                return False
            return handler_execute(self, transforms, *args, **kwargs)

        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class

@require_basic_auth
@url(r'/(?:user/(.+))?/?(?:wd/(.+))?')
class Index(Route):
    def get(self, user, path, basicauth_user, basicauth_pass):
        if not tornado.options.options.unsecure and user:
            return self.redirect(tornado.options.options.redirect_404)
        if tornado.options.options.password:
            if tornado.options.options.password != basicauth_pass:
                return self.redirect(tornado.options.options.redirect_404)
        if user is not None and user != basicauth_user:
            return self.redirect(tornado.options.options.redirect_404)
        else:
            self.set_secure_cookie("user", basicauth_user)
            return self.render('index.html')


@url(r'/style.css')
class Style(Route):

    def get(self):
        default_style = os.path.join(
            os.path.dirname(__file__), 'static', 'main.css')

        css = utils.get_style()

        self.set_header("Content-Type", "text/css")

        if css:
            self.write(css)
        else:
            with open(default_style) as s:
                while True:
                    data = s.read(16384)
                    if data:
                        self.write(data)
                    else:
                        break
        self.finish()

@url(r'/ws(?:/user/([^/]+))?/?(?:/wd/(.+))?')
class TermWebSocket(Route, tornado.websocket.WebSocketHandler):
    terminals = set()

    def pty(self):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            self.shell()
        else:
            self.communicate()

    def shell(self):

        if self.callee is None and (
                tornado.options.options.unsecure and
                tornado.options.options.login):
            # If callee is now known and we have unsecure connection
            user = input('login: ')
            try:
                self.callee = utils.User(name=user)
            except:
                self.callee = utils.User(name='nobody')
        elif (tornado.options.options.unsecure and not
              tornado.options.options.login):
            # if login is not required, we will use the same user as
            # butterfly is executed
            self.callee = utils.User()

        assert self.callee is not None

        try:
            os.chdir(self.path or self.callee.dir)
        except:
            pass

        env = os.environ
        # If local and local user is the same as login user
        # We set the env of the user from the browser
        # Usefull when running as root
        if self.caller == self.callee:
            env.update(self.socket.env)
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "butterfly"
        env["HOME"] = self.callee.dir
        env["LOCATION"] = "http%s://%s:%d/" % (
            "s" if not tornado.options.options.unsecure else "",
            tornado.options.options.host, tornado.options.options.port)
        env["PATH"] = '%s:%s' % (os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'bin')), env.get("PATH"))

        if not tornado.options.options.unsecure or (
                self.socket.local and
                self.caller == self.callee and
                server == self.callee
        ) or not tornado.options.options.login:
            # User has been auth with ssl or is the same user as server
            # or login is explicitly turned off
            if (
                    not tornado.options.options.unsecure and
                    tornado.options.options.login and not (
                        self.socket.local and
                        self.caller == self.callee and
                        server == self.callee
                    )):
                # User is authed by ssl, setting groups
                try:
                    os.initgroups(self.callee.name, self.callee.gid)
                    os.setgid(self.callee.gid)
                    os.setuid(self.callee.uid)
                except:
                    print('The server must be run as root '
                          'if you want to log as different user\n')
                    sys.exit(1)

            args = [tornado.options.options.shell or self.callee.shell]
            args.append('-i')
            os.execvpe(args[0], args, env)
            # This process has been replaced

        # Unsecure connection with su
        if server.root:
            if self.socket.local:
                if self.callee != self.caller:
                    # Force password prompt by dropping rights
                    # to the daemon user
                    os.setuid(daemon.uid)
            else:
                # We are not local so we should always get a password prompt
                if self.callee == daemon:
                    # No logging from daemon
                    sys.exit(1)
                os.setuid(daemon.uid)

        if os.path.exists('/usr/bin/su'):
            args = ['/usr/bin/su']
        else:
            args = ['/bin/su']

        if sys.platform == 'linux':
            args.append('-p')
            if tornado.options.options.shell:
                args.append('-s')
                args.append(tornado.options.options.shell)
        args.append(self.callee.name)
        print args
        os.execvpe(args[0], args, env)

    def communicate(self):
        fcntl.fcntl(self.fd, fcntl.F_SETFL, os.O_NONBLOCK)

        def utf8_error(e):
            self.log.error(e)

        self.reader = io.open(
            self.fd,
            'rb',
            buffering=0,
            closefd=False
        )
        self.writer = io.open(
            self.fd,
            'wt',
            encoding='utf-8',
            closefd=False
        )
        ioloop.add_handler(
            self.fd, self.shell_handler, ioloop.READ | ioloop.ERROR)

    def open(self, user, path):
        if self.get_secure_cookie("user") != user:
            self.on_close()
            self.close()
        self.fd = None
        if self.request.headers['Origin'] not in (
                'http://%s' % self.request.headers['Host'],
                'https://%s' % self.request.headers['Host']):
            self.log.warning(
                'Unauthorized connection attempt: from : %s to: %s' % (
                    self.request.headers['Origin'],
                    self.request.headers['Host']))
            self.close()
            return

        self.socket = utils.Socket(self.ws_connection.stream.socket)
        self.set_nodelay(True)
        self.log.info('Websocket opened %r' % self.socket)
        self.path = path
        self.user = user.decode('utf-8') if user else None
        self.caller = self.callee = None

        # If local we have the user connecting
        if self.socket.local and self.socket.user is not None:
            self.caller = self.socket.user

        if tornado.options.options.unsecure:
            if self.user:
                try:
                    self.callee = utils.User(name=self.user)
                except LookupError:
                    self.callee = None

            # If no user where given and we are local, keep the same user
            # as the one who opened the socket
            # ie: the one openning a terminal in borwser
            if not self.callee and not self.user and self.socket.local:
                self.callee = self.caller
        else:
            user = utils.parse_cert(self.stream.socket.getpeercert())
            assert user, 'No user in certificate'
            self.user = user
            try:
                self.callee = utils.User(name=self.user)
            except LookupError:
                raise Exception('Invalid user in certificate')

        TermWebSocket.terminals.add(self)

        self.write_message(senseMotd(self.socket))
        self.pty()

    def on_message(self, message):
        if not hasattr(self, 'writer'):
            self.on_close()
            self.close()
            return
        if message[0] == 'R':
            cols, rows = map(int, message[1:].split(','))
            s = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, s)
            self.log.info('SIZE (%d, %d)' % (cols, rows))
        elif message[0] == 'S':
            self.log.info('WRIT<%r' % message)
            self.writer.write(message[1:])
            self.writer.flush()
        elif message[0] == 'P':
        	# A ping.
        	pass

    def shell_handler(self, fd, events):
        if events & ioloop.READ:
            try:
                read = self.reader.read()
            except IOError:
                read = ''

            self.log.info('READ>%r' % read)
            if read and len(read) != 0 and self.ws_connection:
                self.write_message(read.decode('utf-8', 'replace'))
            else:
                events = ioloop.ERROR

        if events & ioloop.ERROR:
            self.log.info('Error on fd %d, closing' % fd)
            # Terminated
            self.on_close()
            self.close()

    def on_close(self):
        if self.fd is not None:
            self.log.info('Closing fd %d' % self.fd)

        if getattr(self, 'pid', 0) == 0:
            self.log.info('pid is 0')
            return

        try:
            ioloop.remove_handler(self.fd)
        except Exception:
            self.log.error('handler removal fail', exc_info=True)

        try:
            os.close(self.fd)
        except Exception:
            self.log.debug('closing fd fail', exc_info=True)

        try:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        except Exception:
            self.log.debug('waitpid fail', exc_info=True)

        TermWebSocket.terminals.remove(self)
        self.log.info('Websocket closed')

        if self.application.systemd and not len(TermWebSocket.terminals):
            self.log.info('No more terminals, exiting...')
            sys.exit(0)
