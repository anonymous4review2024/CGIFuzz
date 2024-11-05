# This is a connection class that sends data via TCP sockets.
# Copyright (c) 2022 Robert Bosch GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from __future__ import annotations

import configparser
import logging as log
import socket
import struct
import time
import traceback

from CGIFuzz.connections.ConnectionBaseClass import ConnectionBaseClass


class TCPConnection(ConnectionBaseClass):
    """TCP Sockets are used to send fuzz data to the target
    """

    def connect(self, SUTConnection_config: configparser.SectionProxy) -> None:
        log.debug("TCPConnection connect")
        self.is_connected = False
        self.hostname = self.SUTConnection_config['target_hostname']
        self.port = self.SUTConnection_config.getint('target_port')
        self.reset_sut()

    def connect_async(self):
        # log.debug(f"TCPConnection.connect_async self.is_connected is {self.is_connected}")
        # log.debug("connect async here\nconnect async here\nconnect async here\nconnect async here\nconnect async here\n")
        self.is_connected = False
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        while not self.is_connected:
            # We need to wait until the SUT started, which may take a while
            try:
                # log.debug(f"Inside TCPConnection.connect_async self.is_connected is {self.is_connected}")
                self.s.connect((self.hostname, self.port))
                self.s.setblocking(True)
                self.is_connected = True
                log.debug(f'Established connection with SUT at {self.hostname=}, {self.port=}')
            except Exception as e:
                log.info(f'Waiting for SUT to open server socket {e}')
                time.sleep(0.5)

    def wait_for_input_request(self) -> None:
        log.debug("TCPConnection wait_for_input_request")
        self.connect_async()

    def send_pre_package(self, pre_package: bytes) -> None:
        log.debug("Pre package send")
        self.s.sendall(pre_package + b"\r\n\r\n")

    def send_input(self, fuzz_input: bytes) -> None:
        log.debug("TCPConnection send_input")
        # We always append the HTTP end sequence
        # log.debug("Sending input here\nSending input here\nSending input here\nSending input here\nSending input here\n")
        self.s.sendall(fuzz_input + b"\r\n\r\n")
        # self.s.sendall(fuzz_input)

        # We ignore receive errors,
        # because they can result from incomplete data while fuzzing
        # try:
        #    self.s.recv(10000)
        # except ConnectionError as e:
        #    log.debug(f"Ignoring {e}")

        # We disconnect after each input to finalize eventual stateful sessions
        self.disconnect()
        log.debug("TCPConnection disconnect")

    def disconnect(self) -> None:
        log.debug("TCPConnection disconnect")
        # log.debug("TCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\n")
        self.s.close()
        self.is_connected = False

# # This is a connection class that sends data via TCP sockets.
# # Copyright (c) 2022 Robert Bosch GmbH
# #
# # This program is free software: you can redistribute it and/or modify
# # it under the terms of the GNU Affero General Public License as published
# # by the Free Software Foundation, either version 3 of the License, or
# # (at your option) any later version.
# #
# # This program is distributed in the hope that it will be useful,
# # but WITHOUT ANY WARRANTY; without even the implied warranty of
# # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# # GNU Affero General Public License for more details.
# #
# # You should have received a copy of the GNU Affero General Public License
# # along with this program.  If not, see <https://www.gnu.org/licenses/>.
# from __future__ import annotations
#
# import configparser
# import logging as log
# import socket
# import struct
# import time
# import traceback
#
# from GDBFuzz.connections.ConnectionBaseClass import ConnectionBaseClass
#
#
# class TCPConnection(ConnectionBaseClass):
#     """TCP Sockets are used to send fuzz data to the target
#     """
#
#     def connect(self, SUTConnection_config: configparser.SectionProxy) -> None:
#         log.debug("TCPConnection connect")
#         self.is_connected = False
#         self.hostname = self.SUTConnection_config['target_hostname']
#         self.port = self.SUTConnection_config.getint('target_port')
#         self.reset_sut()
#
#     def connect_async(self):
#         log.debug(f"TCPConnection.connect_async self.is_connected is {self.is_connected}")
#         # log.debug("connect async here\nconnect async here\nconnect async here\nconnect async here\nconnect async here\n")
#         self.is_connected = False
#         self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
#         while not self.is_connected:
#             # We need to wait until the SUT started, which may take a while
#             try:
#                 log.debug(f"Inside TCPConnection.connect_async self.is_connected is {self.is_connected}")
#                 self.s.connect((self.hostname, self.port))
#                 self.s.setblocking(True)
#                 self.is_connected = True
#                 log.debug(f'Established connection with SUT at {self.hostname=}, {self.port=}')
#             except Exception as e:
#                 log.info(f'Waiting for SUT to open server socket {e}')
#                 time.sleep(0.5)
#
#     def wait_for_input_request(self) -> None:
#         log.debug("TCPConnection wait_for_input_request")
#         self.connect_async()
#
#
#     def send_input(self, fuzz_input: bytes) -> None:
#         log.debug("TCPConnection send_input")
#         # We always append the HTTP end sequence
#         # log.debug("Sending input here\nSending input here\nSending input here\nSending input here\nSending input here\n")
#         self.s.sendall(fuzz_input + b"\r\n\r\n")
#
#         # We ignore receive errors,
#         # because they can result from incomplete data while fuzzing
#         #try:
#         #    self.s.recv(10000)
#         #except ConnectionError as e:
#         #    log.debug(f"Ignoring {e}")
#
#         # We disconnect after each input to finalize eventual stateful sessions
#         # log.debug("Disconnect here\nDisconnect here\nDisconnect here\nDisconnect here\nDisconnect here\n")
#         self.disconnect()
#
#
#     def disconnect(self) -> None:
#         log.debug("TCPConnection disconnect")
#         # log.debug("TCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\nTCPConnection disconnected\n")
#         self.s.close()
#         self.is_connected = False