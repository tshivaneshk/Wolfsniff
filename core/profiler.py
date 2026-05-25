import math
import collections

class AdaptiveProfiler:
    def __init__(self, window_size=1000):
        self.scores = collections.deque(maxlen=window_size)
        self.mean = 0.0
        self.std_dev = 0.0
        
    def update(self, score):
        self.scores.append(score)
        n = len(self.scores)
        if n > 1:
            self.mean = sum(self.scores) / n
            variance = sum((x - self.mean) ** 2 for x in self.scores) / n
            self.std_dev = math.sqrt(variance)
        else:
            self.mean = score
            self.std_dev = 0.0

    def get_z_score(self, score):
        if self.std_dev == 0.0 or len(self.scores) < 5:
            return 0.0
        return (score - self.mean) / self.std_dev
