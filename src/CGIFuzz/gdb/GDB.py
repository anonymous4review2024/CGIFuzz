# This class handles the GDB connection.
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

import logging as log
import multiprocessing
import multiprocessing as mp
import os
import queue
import signal
import time
from typing import Any
from typing import NoReturn

from pygdbmi.gdbcontroller import GdbController


class GDB():
    """Interface to GDB MI API.

    This component starts a GDB Client.
    """

    def __init__(
            self,
            stop_responses: mp.Queue[tuple[str, Any]],
            aditional_hit_addresses: mp.Queue[int],
            software_breakpoint_addresses: list[int],
            consider_sw_breakpoint_as_error: bool,
            gdb_path: str,
            gdb_server_address: str,
            add_one: bool
    ) -> None:
        # message_id associates GDB requests with GDB responses.
        self.message_id: int = 0
        # GDBCommunicator interacts with GDB Client, and runs in a
        # separate process. Use queueus to communicate with this process.
        self.stop_responses = stop_responses
        self.gdb_server_address = gdb_server_address
        self.requests: mp.Queue[str] = mp.Queue()
        self.request_responses: mp.Queue[dict[str, Any]] = mp.Queue()
        # 标记是否需要add_one 针对mips的特例
        self.add_one = bool(add_one)

        self.gdb_communicator = GDBCommunicator(
            self.stop_responses,
            aditional_hit_addresses,
            self.requests,
            self.request_responses,
            software_breakpoint_addresses,
            consider_sw_breakpoint_as_error,
            gdb_path
        )
        self.gdb_communicator.daemon = True
        self.gdb_communicator.start()

    def stop(self) -> None:
        log.debug("Try to stop gdb ...")
        try:
            self.send('-interpreter-exec console "monitor exit"', timeout=1)
        except  Exception as e:
            log.debug(f"gdb -interpreter-exec console 'monitor exit' exception: {e}")

        try:
            self.disconnect()
        except Exception as e:
            log.debug(f"gdb disconnect error: {e}")

        try:
            self.send("-gdb-exit", timeout=0.5)
        except Exception as e:
            log.debug(f"gdb exit error: {e}")
        # self.continue_execution()
        if  self.gdb_communicator and self.gdb_communicator.pid:
            # Send SIGUSR1 signal to the GDBCommunicator process.
            # After the user defined disconnect function returns,
            # GDBCommunicator exits.
            # self.gdb_communicator.running = False
            # time.sleep(0.2)
            log.debug("try to kill the gdb communicator")
            os.kill(self.gdb_communicator.pid, signal.SIGUSR1)
            # self.gdb_communicator.gdbmi.exit()
            self.gdb_communicator.join(timeout=3)

            if self.gdb_communicator.gdbmi and self.gdb_communicator.gdbmi.gdb_process:
                os.kill(self.gdb_communicator.gdbmi.gdb_process.pid, signal.SIGKILL)


            exitcode = self.gdb_communicator.exitcode
            if exitcode != 0:
                #Force killing GDB processes
                if self.gdb_communicator.gdbmi and self.gdb_communicator.gdbmi.gdb_process:
                    os.kill(self.gdb_communicator.gdbmi.gdb_process.pid, signal.SIGKILL)
                os.kill(self.gdb_communicator.pid, signal.SIGKILL)
                time.sleep(1)
                raise Exception(f'gdb_manger process exited with {exitcode=}.')
            log.debug("gdb communicator killed !")
        log.debug("GDB stop success!")

    def send(self, message: str, timeout: int = 10) -> dict[str, Any]:
        """Send a request to the GDB process, wait and return the response.
        Raise TimeoutError if no response was received within 'timeout'
        seconds.
        """
        log.debug("GDB send message")
        message_id = self.generate_message_id()
        message = str(message_id) + message
        self.requests.put(message)
        timeout_time = time.time() + timeout
        while True:
            timeout_seconds_left = timeout_time - time.time()
            try:
                # Raises queue.Empty if .get() times out.
                response = self.request_responses.get(
                    block=True,
                    timeout=timeout_seconds_left
                )
            except queue.Empty:
                raise TimeoutError(
                    f'No response was received for request "{message}" within'
                    f'timeout: {timeout} seconds.'
                )
            if response['token'] == message_id:
                return response
            # Skip responses that are from previous sync requests that timed
            # out, check next response.
        log.debug("Gdb send message over")

    # 从stop_response队列中获取一条信息
    def wait_for_stop(self, timeout: float = 360000) -> tuple[str, Any]:
        """Wait for the SUT to stop, returns why the SUT stopped.

        Call this function only if the SUT is currently running.
        """
        try:
            # Raises queue.Empty if .get() times out.
            msg = self.stop_responses.get(block=True, timeout=timeout)
        except queue.Empty:
            return ('timed out', None)
        return msg

    def clear_stop_responses(self):
        while not self.stop_responses.empty():
            try:
                self.stop_responses.get_nowait()
            except multiprocessing.queues.Empty:
                break

    # All of the following functions in this class provide python functions
    # for GDB commands. All of these functions use self.send to send this
    # command.

    def connect(self) -> None:
        log.info(
            f'Trying to connect to GDB Server at {self.gdb_server_address}')
        # self.send('-gdb-set mi-async on')
        self.send(f'-target-select extended-remote {self.gdb_server_address}', timeout=1)
        # self.send('-gdb-set follow-fork-mode parent')


    def set_follow_fork_mode_parent(self) -> None:
        self.send('-gdb-set follow-fork-mode parent')


    def disconnect(self) -> None:
        self.send('-target-disconnect',timeout=1)

    def continue_execution(self, retries: int = 3) -> None:
        gdb_response = self.send('-exec-continue --all')
        if gdb_response['message'] == 'error':
            # Occurs e.g. if the program is not running currently.
            if gdb_response["payload"]["msg"] == 'The program is not being run.':
                self.stop_responses.put(
                    ('program exit', gdb_response["payload"]["msg"])
                )
                return False
            if retries == 0:
                pass
                #raise Exception(gdb_response['payload']['msg'])
            else:
                # Retry
                log.warning(
                    f'Warning, continue_execution() failed due to '
                    f'{gdb_response["payload"]["msg"]}.\n'
                    f'Trying continue_execution() again in 0.5 seconds'
                )
                time.sleep(0.5)
                self.continue_execution(retries - 1)

    def interrupt(self) -> None:
        # self.send('-exec-continue --all')
        self.send('-exec-interrupt --all')
        # self.send('-gdb-exit')
        # self.send('-target-detach')

    def set_breakpoint(self, address: int, is_hardware_bp: bool = True) -> str:
        """Returns the ID that GDB gave to the breakpoint."""
        if self.add_one == True:
            address = address + 1
        if is_hardware_bp:
            # gdb_response = self.send(f'-break-insert -h *{hex(address)}')
            gdb_response = self.send(f'-break-insert *{hex(address)}')
        else:
            gdb_response = self.send(f'-break-insert *{hex(address)}')
        assert 'type' in gdb_response
        assert gdb_response['type'] == 'result'
        if gdb_response['message'] != 'done':
            raise Exception(
                f'Failed to set breakpoint at address {hex(address)}')
        bp_id: str = gdb_response['payload']['bkpt']['number']
        return bp_id

    def set_breakpoint_on_name(self, name: str) -> str:
        gdb_response = self.send(f"-break-insert {name}")
        if 'type' in gdb_response and gdb_response['type'] == 'result' and gdb_response['message'] == 'done':
            bp_id: str = gdb_response['payload']['bkpt']['number']
            return bp_id
        else:
            return False


    def remove_breakpoint(self, breakpoint_id: str) -> None:
        # breadkpoint id is returned by gdb if we set_breakpoint
        self.send(f'-break-delete {breakpoint_id}')

    def step_instruction(self) -> None:
        response = self.send('-exec-step-instruction')
        if response['message'] == 'error':
            raise Exception(str(response))

    def read_register(
            self,
            register_number: int,
            output_format: str = 'x'
    ) -> int:
        response = self.send(
            f'-data-list-register-values {output_format} {register_number}'
        )
        if (
                response['message'] == 'error' or
                len(response['payload']['register-values']) != 1
        ):
            raise Exception(str(response))
        return int(response['payload']['register-values'][0]['value'], 16)

    def read_memory(self, address: int, size: int) -> int:
        response = self.send(f'-data-read-memory-bytes {address} {size}')
        if 'memory' not in response['payload']:
            raise Exception(f'GDB memory request failed {response=}')
        return int(response['payload']['memory'][0]['contents'], 16)

    def register_name_to_number(self) -> dict[str, int]:
        ret = {}
        response = self.send('-data-list-register-names')
        register_list = response['payload']['register-names']
        for i, register_name in enumerate(register_list):
            ret[register_name] = i
        return ret

    def generate_message_id(self) -> int:
        self.message_id += 1
        return self.message_id


class GDBCommunicator(mp.Process):
    def __init__(
            self,
            stop_responses: mp.Queue[tuple[str, Any]],
            aditional_hit_addresses: mp.Queue[int],
            requests: mp.Queue[str],
            request_responses: mp.Queue[dict[str, Any]],
            software_breakpoint_addresses: list[int],
            consider_sw_breakpoint_as_error: bool,
            gdb_path: str
    ) -> None:
        super().__init__()
        self.software_breakpoint_addresses = software_breakpoint_addresses
        self.consider_sw_breakpoint_as_error = consider_sw_breakpoint_as_error
        self.stop_responses = stop_responses
        self.aditional_hit_addresses = aditional_hit_addresses
        self.requests = requests
        self.request_responses = request_responses
        self.gdbmi = GdbController(
            gdb_path.split() + ["--nx", "--quiet", "--interpreter=mi3"]
        )
        self.running = True

        self.console_messages: list[dict[str, Any]] = []

    # 总体来说，这段代码实现了一个长时间运行的循环，负责从请求队列中获取请求并发送给GDB，同时从GDB获取响应，并根据响应的类型进行不同的处理。
    def run(self) -> NoReturn:
        # Install signal handler for SUGUSR1, which is sent when
        # this instance should exit. This instance should exit
        # when the target system is restarted.
        log.debug("GDBCommunicator is running")
        signal.signal(signal.SIGUSR1, self.on_exit)

        while self.running:
            # log.debug("GDBCommunicator run\nGDBCommunicator run\nGDBCommunicator run\nGDBCommunicator run\nGDBCommunicator run\n")
            # Forward all requests to GDB.
            while not self.requests.empty() and self.running:
                request = self.requests.get(block=False)
                log.debug(f'GDBCommunicator send message: {request}')
                self.console_messages = []
                self.gdbmi.write(request, read_response=False, timeout_sec=0)

            # Receive all GDB responses.
            try:
                if self.running:
                    responses = self.gdbmi.get_gdb_response(
                        timeout_sec=0,
                        raise_error_on_timeout=False
                    )
            except Exception as e:
                log.error(f'Exception from get_gdb_response: {e}')
                raise e
            # log.debug(f"GDBCommunicator responses: {responses}")
            # Process responses. That is, classify them, extract relevant
            # information from them, and pass the back to the GDB Python class
            # instance via one of the queues.
            for response in responses:
                log.debug(f'Received and try to deal the response: {response}')
                if 'token' in response and response['token'] is not None:
                    log.debug(f"The response is a console message and have token, so try to put it in the request_response")
                    response['console_data'] = self.console_messages
                    self.console_messages = []
                    self.request_responses.put(response)
                elif 'type' in response and response['type'] == 'console':
                    log.debug(f"The response is a console message, try to put it in the console_message")
                    self.console_messages.append(response)
                else:
                    log.debug(f'The response is a stop message, and try to deal it')
                    self.on_stop_response(response)

    def on_exit(self, signum: Any, frame: Any) -> None:
        self.running = False
        # log.debug("gdb mi debug here\ngdb mi debug here\ngdb mi debug here\ngdb mi debug here\ngdb mi debug here\n")
        # ret = self.gdbmi.exit()
        # log.debug("1GDBmi exit\n1GDBmi exit\n1GDBmi exit\n1GDBmi exit\n1GDBmi exit\n1GDBmi exit\n")
        process = self.gdbmi.gdb_process
        if process:
            try:
                process.terminate()
                # process.communicate(timeout=1)
            except TimeoutError as e:
                log.warning(f"Timeout error on stopping GDB: {e}")
                os.kill(process.pid, signal.SIGKILL)
        # self.gdbmi.exit()
        # log.debug("GDBmi exit\nGDBmi exit\nGDBmi exit\nGDBmi exit\nGDBmi exit\nGDBmi exit\n")
        #exit(0)

    def on_stop_response(self, response: dict[str, Any]) -> None:
        """Parse 'response', if the response specifies that the SUT has
        stopped, put the parsed response onto the self.stop_responses queue.
        """
        if (
                response['type'] == 'notify' and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'reason' in response['payload'] and
                response['payload']['reason'] == 'breakpoint-hit' and
                'bkptno' in response['payload']
        ):
            # Hardware breakpoint hit.
            log.debug(f"stop reason : breakpoint hit")
            self.stop_responses.put(
                ('breakpoint hit', response['payload']['bkptno'])
            )
        elif (response['type'] == 'notify' and response['message'] == 'breakpoint-modified'):
            self.stop_responses.put(('breakpoint-modified', response['payload']))
        elif (
                response['type'] == 'notify' and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'reason' in response['payload'] and
                response['payload']['reason'] == 'end-stepping-range'
        ):
            # Single step finished.
            log.debug("stop reason : step instruction done")
            self.stop_responses.put(
                ('step instruction done', response['payload'])
            )
        elif (
                response['type'] == 'notify' and
                response['message'] == 'thread-group-exited'
        ):
            log.debug("stop reason : exited")
            self.stop_responses.put(('exited', ''))
        elif (
                response['type'] == 'log' and
                isinstance(response['payload'], str) and
                response['payload'].startswith('Remote communication error')
        ):
            # Failed to communicate with the GDB Server. Manager
            # treats this like a crash of the target system.
            log.debug("stop reason : remote communication error")
            self.stop_responses.put(
                ('communication error', response['payload'])
            )
        # mycode
        elif (
                (response['type'] == 'log' or
                response['type'] == 'result') and
                ((isinstance(response['payload'], dict) and
                isinstance(response['payload']['msg'], str) and
                str(response['payload']).find('The program is not being run.') != -1) or
                 (str(response['payload']).find('Remote connection closed') != -1))
                # response['payload'].startswith('Remote communication error')
        ):
            # Failed to communicate with the GDB Server. Manager
            # treats this like a crash of the target system.
            log.debug("stop reason : program exit")
            self.stop_responses.put(
                ('program exit', str(response['payload']))
            )
        #     mycode
        elif (
                response['type'] == 'notify' and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'signal-meaning' in response['payload'] and
                (
                    response['payload']['signal-meaning'] in
                    ['Interrupt', 'Trace/breakpoint trap', 'Signal 0']
                )

        ):
            # With QEMU, 'signal-meaning' is 'Interrupt', on stlink it is
            # 'trace/breakpoint trap'.
            pc = int(response['payload']['frame']['addr'], 16)
            if pc in self.software_breakpoint_addresses or self.consider_sw_breakpoint_as_error:
                # Software breakpoint that is set at error handling code
                # was hit.
                # gdb-multiarch does emit this response code on a normal interrupt request, as well :(
                log.debug("stop reason : crashed")
                self.stop_responses.put(
                    ('crashed', str(response['payload']))
                )
            else:
                # Either a watchpoint is hit or the target system
                # was interrupted. In both cases, the response looks the same.
                # The Manager knows when it interrupts
                # the target system and therefore the Manger can differentiate
                # between these two cases.
                log.debug("stop reason : interrupt")
                self.stop_responses.put(
                    ('interrupt', int(
                        response['payload']['frame']['addr'], 16))
                )
        elif (
                response['type'] == 'notify' and
                response['message'] == 'stopped' and
                isinstance(response['payload'], dict) and
                'signal-meaning' in response['payload'] and
                (response['payload']['signal-meaning'] == 'Aborted' or response['payload']['signal-meaning'] == "Segmentation fault")
        ):
            log.debug("stop reason : crashed")
            self.stop_responses.put(
                ('crashed', str(response['payload']))
            )
        elif (
                response['type'] == 'notify' and
                str(response['payload']).find("'func': '_start'")==-1 and
                response['message'] == 'stopped'
        ):
            log.debug("stop reason : stopped, no reason given")
            self.stop_responses.put(
                ('stopped, no reason given', str(response))
            )

        #This extra branch handles the weird responses from the xtensa gdb :/
        elif (
                response['type'] == 'target' and
                response['message'] == None and
                'Target halted' in response['payload']
        ):
            payload = response['payload'].split(', ')
            for chunk in payload:
                key_val = chunk.split('=')
                if key_val[0] == 'PC':
                    # We push hit addresses to the seperate Queue to avoid having
                    # multiple stop responses for a single interruption
                    self.aditional_hit_addresses.put(int(key_val[1], 16))
                    log.debug(f"PC at {key_val[1]}")


