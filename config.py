# defines the base transport layer
TRANSPORT = "UDP"

# the maximum timeout before communicatin closes
TIMEOUT_MAX_MS = 2000

# block size is used when padding for AES
BLOCK_SIZE = 16

# maxQueueSize = 1000
BUFFER_SIZE = 1024

# waiter ip and port
WAITER = ("127.0.0.1", 3000)

# kitchen ip and port
KITCHEN = ("127.0.0.1", 3001)