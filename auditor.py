from datetime import datetime
import os, stat
import pickle
from threading import Lock

class AuditEntry(object):
    def __init__(self, time, operation, userId, ipAddr, reason):
        self.time = time
        self.operation = operation
        self.userId = userId
        self.ipAddr = ipAddr
        self.reason = reason

    def toDict(self):
        entry = {}
        entry["time"] = self.time
        entry["op"] = self.operation
        entry["uid"] = self.userId
        entry["remote_ip"] = self.ipAddr
        entry["reason"] = self.reason
        return entry

class Auditor:
    def __init__(self, auditFile):
        self.file = auditFile
        if(not os.path.exists(auditFile)):
            # Create file if not exists.
            self.handle = open(auditFile, 'a+')
            try:
                os.chflags(auditFile, stat.UF_APPEND|stat.SF_APPEND)
            except:
                pass
                
            self.handle.close()
        # TODO: some exclusive lock for the file to stop other processes from reading it.
        self.handle = open(auditFile, 'r+b')
        self.mutex = Lock()

    def pushEvent(self, operation, userId, ipAddr, reason):
        eventTime = datetime.now()
        self.mutex.acquire()
        entry = AuditEntry(eventTime, operation, userId, ipAddr, reason)
        self.handle.seek(0, os.SEEK_END)
        pickle.dump(entry, self.handle)
        # Ensure log is pushed to disk properly, not buffered.
        self.handle.flush()
        os.fsync(self.handle)
        self.mutex.release()

    def readLogs(self):
        # Read all logs and parse into dictionary object.
        self.mutex.acquire()
        self.handle.seek(0, os.SEEK_SET)
        logs = []
        while 1:
            try:
                e = pickle.load(self.handle)
                # Convert from object to dictionary
                logs.append(e.toDict())
            except (EOFError, pickle.UnpicklingError):
                break
        self.mutex.release()
        return logs

if __name__ == "__main__":
    # Some test code...
    auditor = Auditor("audit.log")
    auditor.pushEvent("Logging in", "james", "192.168.1.1", "accessing website")
    print(auditor.readLogs())