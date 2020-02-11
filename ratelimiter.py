import time

class RateLimiter():

    def __init__(self, maxRequests, timeLimit):
        self.maxReqs = maxRequests
        self.maxTime = timeLimit
        self.limits = {}

    def canPass(self, ip):
        # Sliding window rate limiter
        if ip in self.limits:
            reqTimes = self.limits[ip]
            
            # Delete old tokens when past timeLimit
            reqs = [x for x in reqTimes if x < time.time() - self.maxTime]
            self.limits[ip] = [x for x in reqTimes if x not in reqs]
            # Too many requests, limit
            if len(self.limits[ip]) >= self.maxReqs:
                return False
            else:
                self.limits[ip].append(time.time())
                return True
        else:
            # New entry, add first
            self.limits[ip] = []
            self.limits[ip].append(time.time())
            return True


if __name__ == "__main__":
    # Some test code...
    r = RateLimiter(5, 10)
    for x in range(0, 10):
        print(x, r.canPass("127.0.0.1"))
        time.sleep(0.5)

    time.sleep(15)
    print("waited", r.canPass("127.0.0.1"))