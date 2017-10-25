import socket
import subprocess
import time
import logging
import re
import os

from testflow2 import ERROR_MSG_PATTERN
from utils import printName, timeout, handleLogDir, handleAccountsFile
from config import Config
config = Config()
address = config.address
port = config.port
path = config.path
interface = config.interface
serverEndPoint = config.serverEndPoint
LOGGER_PATH = config.LOGGER_PATH

TIMEOUT_LIMIT = 5
REGISTER_REQUEST = R"""REGISTER sip:193.28.87.25:5060 SIP/2.0
Via: SIP/2.0/UDP 10.40.40.49:51515;rport=51515;branch=z9hG4bK-bfojh5usrph4vrod
Max-Forwards: 70
Contact: sip:000999124@193.28.87.25:51515;expires=180
To: sip:000999123@193.28.87.25
From: sip:000999123@193.28.87.25;tag=at6b6oa7byerqtl5
Call-ID: bg1C0CGB6FXiNfp9H!Zj2A!yOLl9@10.40.40.49
CSeq: 1 REGISTER
Expires: 300
User-Agent: SIP self-checker
Content-Length: 0

n=0
n=1
"""

#OK_RESPONSE = R""""""


def process(command, multiConnection=False):
    result = []
    commandResult = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result.append(commandResult)

    if not multiConnection:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        result.append(clientSocket)
    else:
        amountClients = 3
        sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(amountClients)]
        result.append(sockets)

    time.sleep(0.1)
    return tuple(result)

@printName
@timeout(TIMEOUT_LIMIT)
def invalidAccountsFileReturnCode():
    result, clientSocket = process([path, '-p', port, '-l', 'ERROR', '-a', 'foobar.csv'])
    returnCode = result.wait()
    correctReturnCode = 6
    isReturnCodeCorrect = returnCode == correctReturnCode
    reason = None
    if not isReturnCodeCorrect:
        reason = f'Error code is incorrect. Must be {correctReturnCode}, now {returnCode}'
    return isReturnCodeCorrect, reason

@handleLogDir
@printName
@timeout(TIMEOUT_LIMIT)
def invalidAccountsFileReturnCodeInLog():
    result, clientSocket = process([path, '-p', port, '-l', 'ERROR', '-a', 'foobar.csv'])
    result.wait()
    logFile = open(LOGGER_PATH)

    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        for line in logFile:
            logging.debug(f'log: {line[:-1]}')

    logFile.seek(0)

    fileText = logFile.read()
    matches = re.findall(ERROR_MSG_PATTERN,fileText)

    reason = None
    if not matches:
        reason = 'There are no messages about error code in log'
        return False, reason
    returnCode = int(matches[0])
    correctCode = 6
    isReturnCodeCorrect = returnCode == correctCode
    if not isReturnCodeCorrect:
        reason = f'Error code in log is incorrect. Must be {correctCode}, now {returnCode}'
    return isReturnCodeCorrect, reason

@handleAccountsFile
@handleLogDir
@printName
@timeout(TIMEOUT_LIMIT)
def register():
    pathToAccs = Config.ACCOUNTS_FILE_PATH
    os.mkdir('./etc')
    os.mknod(pathToAccs)
    result, clientSocket = process([path, '-p', port, '-l', 'ERROR', '-a',  pathToAccs])
    message = REGISTER_REQUEST
    clientSocket.sendto(message.encode(), serverEndPoint)
    logging.debug(f'<{message}')

    logFile = open(LOGGER_PATH)

    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        for line in logFile:
            logging.debug(f'log: {line[:-1]}')

    data = clientSocket.recv(4096).decode()

    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        for d in data.split('\n'):
            logging.debug(f'> {d}')


    dataLines = data.split('\n')
    isResponseOk = dataLines[0] == "SIP/2.0 200 OK"
    reason = None
    if not isResponseOk:
        reason = "Response is not SIP/2.0 200 OK"
    return isResponseOk, reason

tests = [invalidAccountsFileReturnCode, invalidAccountsFileReturnCodeInLog, register]
