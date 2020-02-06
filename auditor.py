from datetime import datetime
import os
import pickle

class AuditEntry(object):
    def __init__(self, time, operation, userId, ipAddr, reason):
        self.time = time
        self.operation = operation
        self.userId = userId
        self.ipAddr = ipAddr
        self.reason = reason

class Auditor:
    def __init__(self, auditFile):
        self.file = auditFile
        # Create file if not exists.
        self.handle = open("audit.log", 'a+')
        self.handle.close()
        self.handle = open("audit.log", 'r+b')

    def pushEvent(self, operation, userId, ipAddr, reason):
        eventTime = datetime.now()
        entry = AuditEntry(eventTime, operation, userId, ipAddr, reason)
        self.handle.seek(0, os.SEEK_END)
        pickle.dump(entry, self.handle)

    def readLogs(self):
        # Read all logs and parse into JSON object.
        self.handle.seek(0, os.SEEK_SET)
        logs = []
        while 1:
            try:
                logs.append(pickle.load(self.handle))
            except (EOFError, pickle.UnpicklingError):
                break        
        return logs


if __name__ == "__main__":
    auditor = Auditor("audit.log")
    auditor.pushEvent("Logging in", "james", "192.168.1.1", "accessing website")
    print(auditor.readLogs())