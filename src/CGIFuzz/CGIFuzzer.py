from __future__ import annotations

import configparser
import hashlib
import json
import logging as log
import os
import pickle
import re
import time
import uuid
from configparser import ConfigParser
from typing import Any
import dill
import socket

import attr
import networkx as nx
from CGIFuzz import graph
from CGIFuzz import util
from CGIFuzz.breakpoint_strategies.BreakpointStrategy \
    import BreakpointStrategy
from CGIFuzz.fuzz_wrappers.InputGeneration import CorpusEntry, InputGeneration
from CGIFuzz.FuzzerStats import FuzzerStats
from CGIFuzz.gdb.GDB import GDB
from CGIFuzz.ghidra.CFGUpdateCandidate import CFGUpdateCandidate
from CGIFuzz.ghidra.Ghidra import Ghidra
from CGIFuzz.modes.QEMUInstance import QEMUInstance
from CGIFuzz.modes.SUTInstance import SUTInstance
from CGIFuzz.modes.SUTRunsOnHostInstance import SUTRunsOnHostInstance
from CGIFuzz.SUTException import SUTException
from CGIFuzz.visualization.Visualizations import Visualizations
import CGIFuzz.binary_operations.BinaryOperations as BinaryOps


class CGIFuzzer:
    CFG_UPDATE_INTERVAL = 60 * 15  # quarter hour updates

    # Seems like once ghidra times out it never comes back
    MAX_GHIDRA_TIMEOUTS = 1

    def __init__(self, config: ConfigParser, config_file_path: str) -> None:
        self.before_fuzzing(config, config_file_path)

        self.run(config)

        self.after_fuzzing()
        raise SystemExit(0)

    def before_fuzzing(
            self,
            config: ConfigParser,
            config_file_path: str
    ) -> None:
        self.rce_function_breakpoints = None
        self.architecture = BinaryOps.get_architecture(config['SUT']['binary_file_path'])
        self.entrypoint = config['SUT'].getint('entrypoint')
        self.max_breakpoints = config['SUT'].getint('max_breakpoints')
        self.output_directory = \
            config['LogsAndVisualizations']['output_directory']

        self.until_rotate_breakpoints = 20000
        if 'until_rotate_breakpoints' in config['SUT']:
            self.until_rotate_breakpoints = config['SUT'].getint(
                'until_rotate_breakpoints'
            )

        # Addresses of covered basic blocks
        # Add entry point and all dummmy point
        self.covered_nodes: set[int] = {self.entrypoint, -42, -1, -2}

        self.init_fuzzer_stats(config_file_path)
        self.init_components(config)

        self.fuzzer_stats_cfg_update()

        self.crashes_directory = os.path.join(
            self.output_directory,
            'crashes'
        )
        os.mkdir(self.crashes_directory)

        self.rce_vulnerability = os.path.join(
            self.output_directory,
            'rce_vulnerability'
        )
        os.mkdir(self.rce_vulnerability)

        # retrieve dominator relation
        self.dominator_graph = graph.get_semi_global_dominator_graph(
            self.entrypoint,
            self.ghidra.CFG(),
            self.ghidra.exit_Points(),
            self.ghidra.reverse_CFG()
        )

    def init_fuzzer_stats(self, config_file_path: str) -> None:
        self.fuzzer_stats = FuzzerStats()
        self.fuzzer_stats.start_time_epoch = int(time.time())
        self.fuzzer_stats.start_time = \
            time.strftime('%d_%b_%Y_%H:%M:%S_%Z', time.localtime())
        self.fuzzer_stats.config_file_path = config_file_path
        self.write_fuzzer_stats()

    def init_components(self, config: ConfigParser) -> None:
        self.ghidra = Ghidra(
            config['SUT']['binary_file_path'],
            config['SUT'].getboolean('start_ghidra'),
            self.entrypoint,
            config['SUT']['ignore_functions'].split(' '),
            config['Dependencies']['path_to_ghidra'],
            self.output_directory,
            config['Dependencies'].getint('ghidra_port', 0)
        )

        self.visualizations: Visualizations | None = None
        if config['LogsAndVisualizations'].getboolean('enable_UI'):
            self.visualizations = Visualizations(
                self.fuzzer_stats,
                self.output_directory,
                self.ghidra.CFG()
            )
            self.visualizations.daemon = True
            self.visualizations.start()

        self.bp_strategy = self.init_BPS(config)

        seeds_directory: str | None = config['Fuzzer']['seeds_directory']
        if seeds_directory == '':
            seeds_directory = None
        self.input_gen = InputGeneration(
            self.output_directory,
            seeds_directory,
            config['Fuzzer'].getint('maximum_input_length')
        )

    def init_BPS(self, config: ConfigParser) -> BreakpointStrategy:
        breakpoint_strategy_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'breakpoint_strategies',
            config['BreakpointStrategy']['breakpoint_strategy_file']
        )
        BPS_class_name = os.path.splitext(
            os.path.basename(
                config['BreakpointStrategy']['breakpoint_strategy_file']
            )
        )[0]
        BPS_class: Any = util.import_class(
            'imported_BreakpointStrategy_module',
            breakpoint_strategy_path,
            BPS_class_name
        )

        return BPS_class(
            config['SUT'].getint('entrypoint'),
            self.ghidra.CFG(),
            self.ghidra.exit_Points(),
            self.ghidra.reverse_CFG(),
            config['BreakpointStrategy'],
        )

    def init_SUT(self, config: ConfigParser, cfg: nx.DiGraph) -> SUTInstance:
        if config['SUT']['target_mode'] == 'Hardware':
            return SUTInstance(config, cfg)
        if config['SUT']['target_mode'] == 'QEMU':
            return QEMUInstance(config, cfg)
        if config['SUT']['target_mode'] == 'SUTRunsOnHost':
            return SUTRunsOnHostInstance(config, cfg)
        raise Exception(
            'Unknown config target_mode', config['SUT']['target_mode']
        )

    def run(self, config: ConfigParser) -> None:
        single_run_timeout = config['Fuzzer'].getint('single_run_timeout')
        stop_time = config['Fuzzer'].getint('total_runtime') + int(time.time())

        self.inputs_until_breakpoints_rotating = 0  # reset directly

        while stop_time >= int(time.time()):
            with self.init_SUT(config, self.ghidra.CFG()) as sut:
                self.start_fuzzing(
                    sut,
                    single_run_timeout,
                    stop_time,
                    config
                )
                time.sleep(0.5)

            if self.cfg_update_required():
                self.run_update_cfg(self.ghidra.cfg_update_candidates, config)

    def after_fuzzing(self) -> None:
        self.fuzzer_stats.end_time_epoch = int(time.time())

        self.write_fuzzer_stats()

        log.info('Fuzzing finished. Exiting.')

    # 检查数据是否符合要求
    def check_http_packet(self, packet, cgi_name):
        log.debug(f'check_http_packet: {packet}')
        parts = packet.split(b'\r\n\r\n')
        header_lines = parts[0].split(b'\r\n')

        # 检查请求行
        request_line = header_lines[0].split(b' ')
        if len(request_line) != 3 or request_line[0] != b'POST' or b'HTTP' not in request_line[2]:
            log.error(f'Not a HTTP packet')
            return False

        if cgi_name.encode('utf-8') not in request_line[1]:
            log.error("Not target cgi")
            return False

        has_host = any(line.startswith(b'Host:') for line in header_lines)
        has_content_length = any(line.startswith(b'Content-Length:') for line in header_lines)
        if not has_host or not has_content_length:
            log.error("No host or no content length")
            return False

        for line in header_lines[1:]:
            if line and not line.startswith(b' ') and b': ' not in line:
                log.error(f'not like a json format')
                return False
        log.debug(f'check_http_packet success')
        return True


    def http_packet_add_token(self, packet_bytes, new_token):
        log.debug(f'try http_packet_add_token ...')
        packet_str = packet_bytes.decode('utf-8')

        headers, body = packet_str.split('\r\n\r\n', 1)

        try:
            body_json = json.loads(body)
            if 'token' in body_json:
                body_json['token'] = new_token
                body = json.dumps(body_json)
                content_length_line_index = next(
                    i for i, line in enumerate(headers.split('\r\n')) if 'Content-Length:' in line)
                headers_lines = headers.split('\r\n')
                headers_lines[content_length_line_index] = f'Content-Length: {len(body)}'
                headers = '\r\n'.join(headers_lines)
        except json.JSONDecodeError:
            pass

        modified_packet = f'{headers}\r\n\r\n{body}'

        return modified_packet.encode('utf-8')

    def adjust_content_length(self, packet):
        parts = packet.split(b'\r\n\r\n', 1)
        header = parts[0]
        body = parts[1] if len(parts) > 1 else b''

        body_length = len(body)

        try:
            header_str = header.decode('utf-8')
            new_header_str = re.sub(
                r'Content-Length: \d+',
                f'Content-Length: {body_length}',
                header_str
            )

            new_header = new_header_str.encode('utf-8')

            new_packet = new_header + b'\r\n\r\n' + body
            return new_packet
        except Exception as e:
            log.debug(f"Could not decode content-length: {e}")
            return packet

    def send_login_package(self):
        login_packet = '''POST /cgi-bin/login_mgr.cgi HTTP/1.1\r\nHost: 192.168.1.201\r\nContent-Length: 88\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nOrigin: http://192.168.1.201\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6\r\nCookie: username=admin\r\nConnection: keep-alive\r\n\r\ncmd=login&username=admin&pwd=admin&port=&f_type=1&f_username=&pre_pwd=admin&ssl_port=443'''.encode('utf-8')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("192.168.1.201", 80))
            s.sendall(login_packet)



    def send_package(self, sut: SUTInstance, inputs_until_breakpoints_rotating, config):
        """
        This function can update the baseline_input.
        """
        log.debug("send_package start ")
        cgi_name = os.path.basename(config['SUT']['binary_file_path'])
        if 'SUTConnection' in config and 'token' in config['SUTConnection']:
            token = config['SUTConnection']['token']
        else:
            token = None
        inputs_until_breakpoints_rotating -= 1
        if inputs_until_breakpoints_rotating <= 0:
            self.input_gen.choose_new_baseline_input()
        flag = False

        while not hasattr(sut, 'gdb') or not sut.gdb:
            while not flag:
                SUT_input = self.input_gen.generate_input()
                flag = self.check_http_packet(SUT_input, cgi_name)
            if token != None:
                SUT_input = self.http_packet_add_token(SUT_input, token)
            SUT_input = self.adjust_content_length(SUT_input)
            self.send_login_package()
            sut.SUT_connection.send_input(SUT_input)
            log.info(f"SUT_input: {SUT_input}")
            time.sleep(1)
            try:
                self.init_GDB(sut, config)
            except Exception as e:
                sut.gdb.clear_stop_responses()
                log.debug(f"init_GDB exception: {e}, so try again")

        return SUT_input, inputs_until_breakpoints_rotating

    def send_initial_package(self, sut: SUTInstance, inputs_until_breakpoints_rotating):
        inputs_until_breakpoints_rotating -= 1
        if inputs_until_breakpoints_rotating <= 0:
            # inputs_until_breakpoints_rotating = self.until_rotate_breakpoints
            # log.info(f"Redistribute all {self.max_breakpoints} breakpoints")
            self.input_gen.choose_new_baseline_input()
            # self.rotate_breakpoints(sut.gdb, sut.breakpoints, self.input_gen.get_baseline_input())

        # self.rotate_breakpoints(sut.gdb, sut.breakpoints, self.input_gen.get_baseline_input())
        self.fuzzer_stats.runs += 1
        if int(time.time()) > (self.last_stat_update + 60):
            # Update fuzzer stats every minute
            self.write_fuzzer_stats()

        SUT_input = self.input_gen.generate_input()
        sut.SUT_connection.send_input(SUT_input)

        return SUT_input

    def init_GDB(self, sut: SUTInstance, config: ConfigParser):
        sut.gdb: GDB = sut.init_gdb(config)

    def start_fuzzing(
            self,
            sut: SUTInstance,
            single_run_timeout: int,
            stop_time: int,
            config: ConfigParser
    ):
        system_functions = config['SUT']['system_function'].split(" ")
        current_input: bytes = b''
        if hasattr(self, 'breakpoints'):
            sut.breakpoints = self.breakpoints
        stop_reason, stop_info = None, None

        current_input, self.inputs_until_breakpoints_rotating = self.send_package(sut, self.inputs_until_breakpoints_rotating, config)


        while stop_time >= int(time.time()):

            if stop_reason != None and stop_reason != "stopped, no reason given":
                sut.gdb.continue_execution()
                time.sleep(1)

            stop_reason, stop_info = sut.gdb.wait_for_stop(
                timeout=single_run_timeout
            )
            log.debug(f"the current stop reason is !!!! {stop_reason} !!!!")
            if stop_reason == 'input request':

                self.inputs_until_breakpoints_rotating = self.on_input_request(
                    self.inputs_until_breakpoints_rotating,
                    sut,
                    system_functions
                )

                if self.cfg_update_required():
                    return
                self.breakpoints = sut.breakpoints

            #     mycode
            elif stop_reason == 'program exit'  or stop_reason == 'exited':
                time.sleep(0.1)
                log.debug("Program exited")
                return []
            elif stop_reason == "stopped, no reason given":
                continue
            elif stop_reason == "breakpoint-modified":
                continue
            # mycode
            elif stop_reason == 'breakpoint hit':
                self.inputs_until_breakpoints_rotating = \
                    self.until_rotate_breakpoints
                self.on_breakpoint_hit(
                    stop_info,
                    current_input,
                    self.input_gen.get_baseline_input(),
                    sut.gdb,
                    sut.breakpoints
                )
                self.breakpoints = sut.breakpoints
            elif stop_reason == 'interrupt':
                try:
                    additional_bb_id_list = []
                    for bb in sut.get_additional_hit_bbs():
                        bb_id_list = [key for key, value in sut.breakpoints.items() if value == bb]
                        if bb_id_list:
                            additional_bb_id_list.append(bb_id_list[0])
                            self.on_breakpoint_hit(
                                bb_id_list[0],
                                current_input,
                                self.input_gen.get_baseline_input(),
                                sut.gdb,
                                sut.breakpoints
                            )

                    hit_bb = self.ghidra.basic_block_at_address(stop_info)
                    bb_id_list = [key for key, value in sut.breakpoints.items() if value == hit_bb]
                    if bb_id_list:
                        self.on_breakpoint_hit(
                            bb_id_list[0],
                            current_input,
                            self.input_gen.get_baseline_input(),
                            sut.gdb,
                            sut.breakpoints
                        )
                    if not additional_bb_id_list and \
                            not bb_id_list:
                        log.warning(f"Hit non targeted BP. Exception? {stop_reason=} {stop_info=}")
                        self.on_crash(current_input, sut.gdb)

                except Exception as e:
                    log.warning(f"Exception: {e}")
            elif stop_reason == 'timed out':
                self.on_timeout(current_input, sut.gdb)
                return []
            elif stop_reason == 'crashed':
                self.on_crash(current_input, sut.gdb)
                return []
            else:
                log.error(f'Unexpected {stop_reason=} {stop_info=}')
                self.on_crash(current_input, sut.gdb)
                return []

        return []

    def cfg_update_required(
            self
    ) -> bool:

        last_update = 0
        if self.fuzzer_stats.cfg_updates[-1] is None:
            last_update = self.fuzzer_stats.start_time_epoch
        else:
            last_update = self.fuzzer_stats.cfg_updates[-1]['timestamp']

        if self.ghidra.cfg_update_candidates and \
                int(time.time()) - last_update > self.CFG_UPDATE_INTERVAL:
            return True

        return False

    def report_address_reached(
            self,
            current_input: bytes,
            address: int
    ) -> None:
        if address in self.covered_nodes:
            return

        if address not in self.ghidra.CFG():
            log.warn(f'Reached node that is not in CFG: {hex(address)}')
            return

        self.covered_nodes.add(address)
        self.fuzzer_stats.coverage += 1

        self.write_coverage_data(address)

        if self.bp_strategy.coverage_guided():
            self.input_gen.report_address_reached(current_input, address,
                                                  int(time.time()) - self.fuzzer_stats.start_time_epoch)

        self.ghidra.report_address_reached(current_input, address)
        self.bp_strategy.report_address_reached(
            current_input,
            address
        )

        if self.visualizations:
            self.visualizations.new_coverage()

        # Update coverage for dominating parent node.
        # The dominator of the entry point is the entry point itself,
        # so recursion is feasible and ends at the entry point at latest.
        if self.bp_strategy.mark_dominated_nodes():
            try:

                for dominating_parent in self.dominator_graph.predecessors(address):
                    self.report_address_reached(
                        current_input,
                        dominating_parent
                    )
            except nx.NetworkXError as e:
                log.info(f"Node {hex(address)} is not in the dominator graph!")


    def on_crash(
            self,
            current_input: bytes,
            gdb: GDB
    ) -> None:
        log.warn('SUT crash detected')
        self.fuzzer_stats.crashes += 1
        # Get address where crash occured
        try:
            response = gdb.send('-stack-list-frames')
        except TimeoutError:
            # The SUT just crashed, we might not be connected anymore.
            log.warn(
                'Timed out waiting for crashing input stacktrace '
                f'{current_input=}'
            )
            self.write_crashing_input(current_input, str(uuid.uuid4()))
            return
        if 'payload' not in response or 'stack' not in response['payload']:
            log.warn(
                'Invalid payload for crashing input stacktrace '
                f'{current_input=}'
            )
            self.write_crashing_input(current_input, str(uuid.uuid4()))
            return
        stacktrace = ''
        for frame in response['payload']['stack']:
            stacktrace += ' ' + frame['addr']

        # Limit to 100
        if len(stacktrace) > 100:
            stacktrace = stacktrace[0:100]

        # Make string os file name friendly
        stacktrace = "".join([c for c in stacktrace if re.match(r'\w', c)])
        # hashed_stacktrace = hashlib.sha1()
        # hashed_stacktrace.update(stacktrace)
        # stacktrace_digest = hashed_stacktrace.hexdigest()

        self.write_crashing_input(current_input, stacktrace)

    def write_crashing_input(
            self,
            current_input: bytes,
            filename: str
    ) -> None:
        filepath = os.path.join(self.crashes_directory, filename)
        if os.path.isfile(filepath):
            log.info(f'Found duplicate crash with {current_input=}')
            return

        with open(filepath, 'wb') as f:
            log.info(f'New crash with {current_input=}')
            f.write(current_input)

    def on_timeout(
            self,
            current_input: bytes,
            gdb: GDB
    ) -> None:
        try:
            self.fuzzer_stats.timeouts += 1
            stacktrace = ''
            gdb.interrupt()
            # We dont get acknowledge when target system is stopped, so
            # wait for 1 second for target system to stop.
            time.sleep(1)

            response = gdb.send('-stack-list-frames')
            for frame in response['payload']['stack']:
                stacktrace += str(frame['addr']) + ' '
            log.info(f'Timeout input {stacktrace=}')
        except Exception as e:
            log.info(f'Failed to get stacktrace for timeout {e=}')
        if stacktrace is None:
            # use input for deduplication
            stacktrace = current_input
        # Limit to 100
        if len(stacktrace) > 100:
            stacktrace = stacktrace[0:100]

        # Make string os file name friendly
        stacktrace = "".join([c for c in stacktrace if re.match(r'\w', c)])

        filepath = os.path.join(
            self.crashes_directory,
            'timeout_' + stacktrace
        )
        if os.path.isfile(filepath):
            log.info(f'Found duplicate timout input {current_input=}')
            return
        with open(filepath, 'wb') as f:
            log.info(f'Found new timeout {current_input=}')
            f.write(current_input)

    def on_input_request(
            self,
            inputs_until_breakpoints_rotating: int,
            sut: SUTInstance,
            system_functions: list[str]
            # current_input: bytes
    ) -> tuple[bytes, bytes, int]:

        if inputs_until_breakpoints_rotating <= 0:
            inputs_until_breakpoints_rotating = self.until_rotate_breakpoints
            log.info(f"Redistribute all {self.max_breakpoints} breakpoints")
            self.rotate_breakpoints(sut.gdb, sut.breakpoints, self.input_gen.get_baseline_input(), system_functions)
        else:
            # 创建一个临时的字典来存储新的断点
            tmp_breakpoints = {}
            log.debug(f"the baseline input is : \n{self.input_gen.get_baseline_input()}")
            for bp_address in sut.breakpoints.values():
                bp_id = sut.gdb.set_breakpoint(bp_address)
                tmp_breakpoints[bp_id] = bp_address
            sut.breakpoints = tmp_breakpoints
            self.rce_function_breakpoints = self.set_breakpoints_for_rce_functions(sut.gdb, sut.breakpoints, system_functions)
        self.fuzzer_stats.runs += 1
        if int(time.time()) > (self.last_stat_update + 60):
            self.write_fuzzer_stats()

        return inputs_until_breakpoints_rotating

    def get_rce_function(self, bp_id: str):
        for function_name, breakpoint_id in self.rce_function_breakpoints.items():
            if breakpoint_id == bp_id:
                return function_name
        return False

    def substr_match(self, rce_arg_str: str, current_input: bytes, threshold=4) -> [bytes, bool]:
        max_length = 0
        start_index = 0
        rce_arg_bytes = rce_arg_str.encode()

        dp = [[0] * (len(current_input) + 1) for _ in range(len(rce_arg_bytes) + 1)]

        for i in range(1, len(rce_arg_bytes) + 1):
            for j in range(1, len(current_input) + 1):
                if rce_arg_bytes[i - 1] == current_input[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                    if dp[i][j] > max_length:
                        max_length = dp[i][j]
                        start_index = i - 1

        if max_length > threshold:
            start = start_index - max_length + 1
            return rce_arg_bytes[start:start + max_length]
        else:
            return False

    def save_rce_vulnerability(self, match_str: bytes, current_input: bytes, rce_arg_str: str):
        filepath = os.path.join(
            self.rce_vulnerability,
            'rce_' + str(int(time.time()))
        )
        if os.path.isfile(filepath):
            log.debug(f'Found duplicate rce input {current_input=}')
            return
        with open(filepath, 'wb') as f:
            log.info(f'Found new rce vulnerability {current_input=}')
            # f.write(f"rce_function: \n{rce_function.encode()}\n\ncurrent_input: \n{current_input}\n\nrce_arg_str: \n{rce_arg_str.encode()}\n")
            f.write(f"match string: \n".encode())
            f.write(match_str)
            f.write("\n\ncurrent_input: \n".encode())
            f.write(current_input)
            f.write("\n\nrce_arg_str: \n".encode())
            f.write(rce_arg_str.encode())
            f.write("\n".encode())

    def extract_payload_value(self, data: dict):
        """
        Extracts the value of the 'value' key within the 'payload' key from the provided dictionary.

        :param data: Dictionary from which to extract the value.
        :return: The extracted value if both 'payload' and 'value' keys exist, None otherwise.
        """
        # Check if 'payload' and 'value' keys exist in the dictionary
        if 'payload' in data and 'value' in data['payload']:
            return data['payload']['value']
        else:
            return False

    def get_arg_str_of_rce_command(self, gdb: GDB):
        if self.architecture == "MIPS32" or self.architecture == "MIPS64":
            arg_register = "$a0"
        elif self.architecture == "ARM-32":
            arg_register = "$r0"
        elif self.architecture == "ARM-64":
            arg_register = "$x0"
        elif self.architecture == "x86-64":
            arg_register = "$rdi"
        elif self.architecture == "x86":
            arg_register = "$eax"
        else:
            raise Exception("Unsupported architecture")

        log.info(f"architecture: {self.architecture}\nregister: {arg_register} ")
        try:
            response = gdb.send(f'-data-evaluate-expression "(char*){arg_register}"')
            # response = gdb.send(f'-data-evaluate-expression "x /s {arg_register}"')
            if 'message' in response and response['message'] == 'error':
                return False
            rce_arg_str = self.extract_payload_value(response)
            return rce_arg_str
        except Exception as e:
            return False
        # log.info(f'send gdb command: -data-evaluate-expression "(char*){register}"')
        # response = gdb.send(f'-exec-finish')

    def get_func_ret_val(self, gdb: GDB):
        # 待完成
        if self.architecture == "MIPS32" or self.architecture == "MIPS64":
            ret_register = "$v0"
        elif self.architecture == "ARM-32":
            ret_register = "$r0"
        elif self.architecture == "ARM-64":
            ret_register = "$x0"
        elif self.architecture == "x86-64":
            ret_register = "$rax"
        elif self.architecture == "x86":
            ret_register = "$eax"
        else:
            raise Exception("Unsupported architecture")

        try:
            response = gdb.send(f'-exec-finish')
            time.sleep(0.1)
            response = gdb.send(f'i r {ret_register}')
            # Check if 'console_data' is a key in the dictionary
            if 'console_data' in response:
                # Iterate over the items in the 'console_data' list
                for item in response['console_data']:
                    # Check if 'payload' is a key and it is not None
                    if 'payload' in item and item['payload'] and ret_register.replace("$","") in item['payload']:
                        # Try to extract the hexadecimal value from the payload
                        # The payload is expected to be in the format "v0: 0xVALUE\n"
                        # Split the string and remove any escape characters
                        parts = item['payload'].strip().split(' ')
                        # Get the value part and convert it from hexadecimal to integer
                        value = int(parts[-1].replace('\\n', ''), 16)
                        return value
            else:
                return False
        except Exception as e:
            return False


    def deal_rce_function_triggered(
            self,
            rce_function: str,
            current_input: bytes,
            gdb: GDB
    ):
        try:
            rce_arg_str = self.get_arg_str_of_rce_command(gdb)
            if rce_arg_str != False:
                # 成功获取参数值
                match_str = self.substr_match(rce_arg_str, current_input)
                if match_str:
                    ret_val = self.get_func_ret_val(gdb)
                    if ret_val != 0 and ret_val != False:
                        log.info("Find RCE vulnerability")
                        self.save_rce_vulnerability(match_str, current_input, rce_arg_str)
                    else:
                        log.info("Rce function return 0, so it may be safe")
                else:
                    log.info("Rce function arg doesn't match current input, so it may be safe")
                return True
            else:
                #无法获取参数值
                return False
            return True
        except Exception as e:
            # 无法识别指令架构
            log.debug(f"Exception: {e}")
            return False



    def on_breakpoint_hit(
            self,
            bp_id: str,
            current_input: bytes,
            baseline_input: bytes,
            gdb: GDB,
            breakpoints: dict[str, int]
    ) -> None:
        log.debug(f"Entering on_breakpoint_hit function, the bp_id: {bp_id}")
        rce_function = self.get_rce_function(bp_id)
        if not rce_function:
            bp_address = breakpoints[bp_id]
            log.info(f'Breakpoint at {hex(bp_address)} hit.')
            self.fuzzer_stats.breakpoint_interruptions += 1

            covered_before = len(self.covered_nodes)
            self.report_address_reached(current_input, bp_address)

            if self.visualizations:
                self.visualizations.draw_CFG(
                    self.entrypoint,
                    self.ghidra.CFG(),
                    self.covered_nodes
                )
            log.info(
                f'Reached {len(self.covered_nodes) - covered_before}  '
                f'node(s) with a single breakpoint interruption'
            )

            # Relocate breakpoint
            gdb.remove_breakpoint(bp_id)
            del breakpoints[bp_id]
            self.set_breakpoints(gdb, breakpoints, baseline_input)
        else:
            log.debug(f'Breakpoint at function {rce_function}')
            # bp_address = breakpoints[bp_id]
            # self.report_address_reached(current_input, bp_address)
            ret = self.deal_rce_function_triggered(rce_function, current_input, gdb)

    def set_breakpoints_for_rce_functions(
            self,
            gdb: GDB,
            breakpoints: dict[str, int],
            system_functions: list[str]
    ) -> dict:
        rce_function_breakpoints = {}
        for system_function in system_functions:
            bp_id = gdb.set_breakpoint_on_name(system_function)
            if bp_id != False:
                rce_function_breakpoints[system_function] = bp_id
                # breakpoints[bp_id] = rce_function_breakpoints
        # rce_function_breakpoints["system"] = gdb.set_breakpoint_on_name("system")
        # rce_function_breakpoints["popen"] = gdb.set_breakpoint_on_name("popen")
        return rce_function_breakpoints

    # Set up to --max_breakpoints breakpoints.
    def set_breakpoints(
            self,
            gdb: GDB,
            breakpoints: dict[str, int],
            current_baseline_input: bytes
    ) -> None:
        while len(breakpoints) < self.max_breakpoints:
            bp_address = self.bp_strategy.get_breakpoint_address(
                self.covered_nodes,
                set(breakpoints.values()),
                current_baseline_input
            )
            if bp_address is None:
                break
            bp_id = gdb.set_breakpoint(bp_address)
            breakpoints[bp_id] = bp_address

        if self.visualizations:
            self.visualizations.breakpoints_changed(set(breakpoints.values()))

        # gdb.continue_execution()

    def rotate_breakpoints(
            self,
            gdb: GDB,
            breakpoints: dict[str, int],
            baseline_input: bytes,
            system_functions: list[str]
    ) -> None:
        for bp_id in list(breakpoints.keys()):
            gdb.remove_breakpoint(bp_id)
        breakpoints.clear()

        self.set_breakpoints(gdb, breakpoints, baseline_input)
        self.rce_function_breakpoints = self.set_breakpoints_for_rce_functions(gdb, breakpoints, system_functions)

    def run_update_cfg(
            self,
            cfg_update_candidates: list[CFGUpdateCandidate],
            config: ConfigParser
    ) -> None:

        # Only update if we have less than MAX_GHIDRA_TIMEOUTS ghidra failures
        if self.ghidra.ghidra_analysis_fails < self.MAX_GHIDRA_TIMEOUTS:
            for cfg_candidate in cfg_update_candidates:
                with self.init_SUT(config, self.ghidra.CFG()) \
                        as sut:
                    self.ghidra.my_update_cfg(
                        sut,
                        config,
                        # sut.gdb,
                        # sut.SUT_connection,
                        cfg_candidate
                    )
                    # self.gdb.interrupt()
                    sut.gdb.stop()

            self.ghidra.cfg_changed()
            self.bp_strategy.cfg_changed(
                self.entrypoint,
                self.ghidra.CFG(),
                self.ghidra.exit_Points(),
                self.ghidra.reverse_CFG()
            )

            self.fuzzer_stats_cfg_update()

            # retrieve dominator relation
            self.dominator_graph = graph.get_semi_global_dominator_graph(
                self.entrypoint,
                self.ghidra.CFG(),
                self.ghidra.exit_Points(),
                self.ghidra.reverse_CFG()
            )
        else:
            log.warn(
                'Skipping CFG generation because of too many exceptions '
                'previously. Continue using previous version of the CFG.'
            )
            self.ghidra.unknown_edges = {}
            self.ghidra.cfg_update_candidates = []
            return

    def fuzzer_stats_cfg_update(self) -> None:
        nodes_reachable = graph.nodes_reachable(
            self.entrypoint,
            self.ghidra.CFG()
        )
        edges_reachable = graph.edges_reachable(
            self.entrypoint,
            self.ghidra.CFG()
        )
        self.fuzzer_stats.cfg_updates.append(
            {
                'timestamp': int(time.time()),
                'total_basic_blocks': nodes_reachable,
                'total_edges': edges_reachable
            }
        )

    def write_fuzzer_stats(self) -> None:
        self.last_stat_update = int(
            time.time())

        self.fuzzer_stats.runtime = int(
            time.time()) - self.fuzzer_stats.start_time_epoch
        if self.fuzzer_stats.runtime > 1:
            self.fuzzer_stats.runs_per_sec = self.fuzzer_stats.runs / \
                                             self.fuzzer_stats.runtime

        stats_file_path = os.path.join(
            self.output_directory,
            'fuzzer_stats'
        )
        # Print corpus statistics
        if hasattr(self, 'input_gen'):
            self.fuzzer_stats.corpus_state = list(map(CorpusEntry.__str__, self.input_gen.corpus))

        with open(stats_file_path, 'w') as f:
            f.write(json.dumps(
                attr.asdict(self.fuzzer_stats),
                indent=4
            ))

    def write_coverage_data(self, address: int) -> None:
        runtime = int(time.time()) - self.fuzzer_stats.start_time_epoch

        stats_file_path = os.path.join(
            self.output_directory,
            'plot_data'
        )
        with open(stats_file_path, 'a') as f:
            f.write(f'{runtime} {hex(address)}\n')
